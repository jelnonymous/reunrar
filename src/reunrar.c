
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

// must be old, forward from the standard os define
#if !defined(_UNIX) && defined(__unix__)
#define _UNIX __unix__
#endif // !defined(_UNIX) && defined(__unix__)
// Include first due to redundant defines
#include "dll.hpp"

#include <pthread.h>

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

typedef struct timespec Time;

// Thanks, http://www.guyrutenberg.com/2007/09/22/profiling-code-using-clock_gettime/
static inline __attribute((const))
Time time_diff(Time start, Time end) {
	const long k_billion= 1000000000L;
	Time temp;
	if ((end.tv_nsec-start.tv_nsec)<0) {
		temp.tv_sec= end.tv_sec-start.tv_sec-1;
		temp.tv_nsec= k_billion+end.tv_nsec-start.tv_nsec;
	} else {
		temp.tv_sec= end.tv_sec-start.tv_sec;
		temp.tv_nsec= end.tv_nsec-start.tv_nsec;
	}
	return temp;
}

//Thanks, https://codereview.stackexchange.com/questions/40176/correctness-of-calculations-with-struct-timespec
static inline __attribute__((const))
Time time_add(Time t1, Time t2) {
	const long k_billion= 1000000000L;
    long sec= t2.tv_sec + t1.tv_sec;
    long nsec= t2.tv_nsec + t1.tv_nsec;
    if (nsec >= k_billion) {
        nsec-= k_billion;
        sec++;
    }
    return (Time){ .tv_sec= sec, .tv_nsec= nsec };
}

HANDLE load_rar_file(const char *arg_rar_file, unsigned int *out_result_code) {
	char archive_name_storage[256];
	strcpy(archive_name_storage, arg_rar_file);

	struct RAROpenArchiveData arc_data_open;
	memset(&arc_data_open, 0, sizeof(arc_data_open));

	arc_data_open.ArcName= archive_name_storage;
	arc_data_open.OpenMode= RAR_OM_EXTRACT;

	HANDLE arc_handle= RAROpenArchive(&arc_data_open);

	*out_result_code= arc_data_open.OpenResult;

	return arc_handle;
}

int close_rar_file(HANDLE rar_handle) {
	return RARCloseArchive(rar_handle);
}

#ifdef SHORT_GUESS
typedef unsigned int guess_id_t;
#define GUESS_ID_FMT "%u"
#else // SHORT_GUESS
typedef unsigned long long guess_id_t;
#define GUESS_ID_FMT "%llu"
#endif // SHORT_GUESS

//Some huge number
const guess_id_t k_max_guess_id= (1UL<<31)-1;

//Atomically incremented with each thread that attempts a guess
volatile guess_id_t g_current_guess_id=
#ifdef MAGIC_TEST_START
	6911512 /*t*/ + 53816 /*e*/ + 1736 /*s*/ + 28 /*s*/;
#else // DISABLE_TEST_START
	0;
#endif // DISABLE_TEST_START

guess_id_t get_next_password_id() {
	return __sync_add_and_fetch(&g_current_guess_id, 1UL);
}

const char k_password_charset[]= "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const guess_id_t k_password_charset_len= ARRAY_SIZE(k_password_charset)-1;
// for index i, value is the lowest guess id where password len is i
guess_id_t g_guess_to_password_len_lookup[5];

static
void get_password_for_guess_id(guess_id_t guess_id, char *const out_password_store) {

#ifndef TEST_BRANCH_PERF
	int reverse_it;
	guess_id_t password_len;
	//TODO: perfy
	{
		int lookup_it;
		for (lookup_it= ARRAY_SIZE(g_guess_to_password_len_lookup)-1;
				lookup_it>=0 && guess_id < g_guess_to_password_len_lookup[lookup_it];
				--lookup_it) {
		}
		password_len= lookup_it+1;
	}

	out_password_store[password_len]= '\0';
	for (reverse_it= password_len-1; reverse_it>= 0; --reverse_it) {
		out_password_store[reverse_it]= k_password_charset[guess_id % k_password_charset_len];
		guess_id= guess_id/k_password_charset_len;
	}
#else // TEST_BRANCH_PERF
	static char perftest[]= "perftest";
	strcpy(out_password_store, perftest);
	out_password_store[ARRAY_SIZE(perftest)-1]= '0'+guess_id%10;
	out_password_store[ARRAY_SIZE(perftest)]= '\0';
#endif // TEST_BRANCH_PERF
}

//Set to a guess id when a match was found
volatile guess_id_t g_correct_guess_id= 0;

void *run_crack_thread(void *untyped_thread_data) {
	
	HANDLE arc_handle;
	unsigned int open_result_code;

	int read_code= ERAR_SUCCESS;
	struct RARHeaderData arc_data_header;
	const int k_guesses_to_batch= 1; //150;
	int current_guess_index= k_guesses_to_batch;
	guess_id_t guess_store[k_guesses_to_batch];
	const int k_per_password_len= 11;
	const int k_password_store_size= k_per_password_len * k_guesses_to_batch;
	char password_store[k_password_store_size];

#if defined(MAX_GUESS_LOOPS)
	int guess_loop_count= 0;
#endif // defined(MAX_GUESS_LOOPS)

#ifdef PERF_TIMINGS
	Time total_password_time= { 0 };
	Time total_attempt_time= { 0 };
	Time temp_before_time;
	Time temp_after_time;
#endif // PERF_TIMINGS

	arc_handle= load_rar_file((const char *)untyped_thread_data, &open_result_code);

	if (arc_handle) {
		int read_header_code;
		while (g_correct_guess_id==0 && read_code==ERAR_SUCCESS) {
			if (current_guess_index >= k_guesses_to_batch)
			{
#ifdef PERF_TIMINGS
				clock_gettime(CLOCK_REALTIME, &temp_before_time);
#endif // PERF_TIMINGS

				//Fetch our guess store
				int guess_it;
				for (guess_it= 0; guess_it < k_guesses_to_batch; ++guess_it) {
					guess_store[guess_it]= get_next_password_id();
					get_password_for_guess_id(
						guess_store[guess_it],
						&password_store[guess_it*k_per_password_len]);
				}
				current_guess_index= 0;

#ifdef PERF_TIMINGS
				clock_gettime(CLOCK_REALTIME, &temp_after_time);
				temp_after_time= time_diff(temp_before_time, temp_after_time);
				total_password_time= time_add(temp_after_time, total_password_time);
#endif // PERF_TIMINGS
			}

#ifdef PERF_TIMINGS
			clock_gettime(CLOCK_REALTIME, &temp_before_time);
#endif // PERF_TIMINGS

			int header_count= 0;
			do {

				++header_count;
				memset(&arc_data_header, 0, sizeof(arc_data_header));
				read_header_code= RARReadHeader(arc_handle, &arc_data_header);
				read_code= read_header_code;

				if (read_header_code==ERAR_END_ARCHIVE) {
					//TODO: Validate that we saw at least one header
					//Repeat
					read_code= ERAR_SUCCESS;
				} else if (read_header_code!=ERAR_SUCCESS) {
					fprintf(stderr, "Header %d returned code: %#010x\n",
						header_count, read_header_code);
				} else if ((arc_data_header.Flags&RHDF_ENCRYPTED)==0) {
					fprintf(stderr, "File '%s' wasn't encrypted, stopping.\n",
						arc_data_header.FileName);

					read_code= read_header_code= ERAR_UNKNOWN;
				} else {
					// let's do it
					RARSetPassword(arc_handle, &password_store[current_guess_index*k_per_password_len]);

					int test_file_code= RARProcessFile(arc_handle, RAR_TEST, NULL, NULL);
					switch (test_file_code) {
						case ERAR_SUCCESS:
							// Expecting exactly one thread to set this, ever
							//TODO assert that?
							g_correct_guess_id= guess_store[current_guess_index];
							break;

						case ERAR_BAD_PASSWORD: // fallthrough
						case ERAR_BAD_DATA: break;

						default:
							fprintf(stderr, "File '%s': %#010x\n",
									arc_data_header.FileName, test_file_code);
							read_code= ERAR_BAD_DATA;
							read_header_code= ERAR_UNKNOWN;
							break;
					}
				}
			} while (read_header_code==ERAR_SUCCESS);

			if (read_code==ERAR_SUCCESS) {
				read_code= RARSeekBeginning(arc_handle);
				if (read_code != ERAR_SUCCESS) {
					fprintf(stderr, "Seek returned code %#010x\n", read_code);
				}
			}

			++current_guess_index;

#ifdef PERF_TIMINGS
			clock_gettime(CLOCK_REALTIME, &temp_after_time);
			temp_after_time= time_diff(temp_before_time, temp_after_time);
			total_attempt_time= time_add(temp_after_time, total_attempt_time);
#endif // PERF_TIMINGS

#if defined(MAX_GUESS_LOOPS) && MAX_GUESS_LOOPS>0
			if (++guess_loop_count > MAX_GUESS_LOOPS) {
				break;
			}
#endif // defined(MAX_GUESS_LOOPS) && MAX_GUESS_LOOPS>0
		}

		close_rar_file(arc_handle);
	} else {
		//TODO: fatal?
	}

#ifdef PERF_TIMINGS
	printf("Total password time: %llds, %.3f ms\n", (long long)total_password_time.tv_sec, (total_password_time.tv_nsec/1000000.f));
	printf("Total attempt time: %llds, %.3f ms\n", (long long)total_attempt_time.tv_sec, (total_attempt_time.tv_nsec/1000000.f));
#endif // PERF_TIMINGS

	return NULL;
}

volatile bool g_cancel_status_thread= false;

void *run_status_thread(void *unused) {
	
	char password_store[256];
	guess_id_t last_guess_id= g_current_guess_id;

	while (!g_cancel_status_thread) {
		sleep(1);

		guess_id_t current_guess_id= g_current_guess_id;
		get_password_for_guess_id(current_guess_id, password_store);

		printf("'%s', " GUESS_ID_FMT " passwords/s\n",
			password_store, current_guess_id-last_guess_id);
		last_guess_id= current_guess_id;
	}

	return NULL;
}

int main(int argc, char **argv) {

	if (argc < 2) {
		fprintf(stderr, "Usage: reunrar file.rar\n");
		return 1;
	}

	const char *const arg_rar_file= argv[1];
	//TODO: Seed password? e.g., from status file

	HANDLE arc_handle;
	unsigned int open_result_code;

	arc_handle= load_rar_file(arg_rar_file, &open_result_code);

	if (arc_handle) {

		//Initial load test passed, close and let threads take it from here
		close_rar_file(arc_handle);

		//Initialize some things
		const guess_id_t initial_guess_id= g_current_guess_id;
		{
			int i;
			for (i= 0; i<ARRAY_SIZE(g_guess_to_password_len_lookup); ++i) {
				g_guess_to_password_len_lookup[i]= powl(strlen(k_password_charset), i);
			}
		}

#ifndef DISABLE_THREADS
		{
			pthread_t crack_threads[4];
			pthread_t status_thread;
			int it;

			puts("Spinning up threads...");

			for (it= 0; it < ARRAY_SIZE(crack_threads); ++it) {
				if(pthread_create(&crack_threads[it], NULL, run_crack_thread, (void*)arg_rar_file)) {
					fprintf(stderr, "Fatal error creating thread %d\n", it);
					//TODO: return? better to cancel out somehow
				}
			}

			if(pthread_create(&status_thread, NULL, run_status_thread, NULL)) {
				fprintf(stderr, "Fatal error creating status thread\n");
				//TODO: return? better to cancel out somehow
			}

			for (it= 0; it < ARRAY_SIZE(crack_threads); ++it) {
				int join_result= pthread_join(crack_threads[it], NULL);
				if(join_result != 0) {
					fprintf(stderr, "Fatal error joining thread %d: %d\n", it, join_result);
					//TODO: return? better to cancel out somehow
				}
			}

			// cancel status thread
			g_cancel_status_thread= true;

			int join_result= pthread_join(status_thread, NULL);
			if(join_result != 0) {
				fprintf(stderr, "Fatal error joining status thread: %d\n", join_result);
			}
		}

#else // DISABLE_THREADS
		run_crack_thread((void*)arg_rar_file);
#endif // DISABLE_THREADS

		{
			char password_store[256];

			if (g_correct_guess_id != 0) {
				get_password_for_guess_id(g_correct_guess_id, password_store);
				printf("Success! Password: %s\n", password_store);
			} else {
				get_password_for_guess_id(g_current_guess_id, password_store);
				printf("Failure :( ... made it to '%s' (" GUESS_ID_FMT " guesses)\n",
					password_store, g_current_guess_id-initial_guess_id);
			}
		}

	} else {
		fprintf(stderr, "Failed to open archive '%s'\n", arg_rar_file);
		fprintf(stderr, "Error code: %#010x\n", open_result_code);
	}
	
	return 0;
}

