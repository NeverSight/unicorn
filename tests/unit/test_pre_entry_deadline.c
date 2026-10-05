/* Original pre-entry deadline regression, NeverD contributors, 2026-09-30.
 * Licensed under the same terms as the Unicorn unit tests. */
#include "unicorn_test.h"

#include <errno.h>
#include <pthread.h>

#define UC_DEADLINE_VALUE(Name, Value) static const uint64_t Name = Value;
#include "pre_entry_deadline.def"
#undef UC_DEADLINE_VALUE

static pthread_mutex_t Lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t Ready = PTHREAD_COND_INITIALIZER;
static bool Done, Delay;
struct ThreadCall {
  void *(*Routine)(void *);
  void *Argument;
};
extern int __real_pthread_create(pthread_t *, const pthread_attr_t *,
                                 void *(*)(void *), void *);

static void *complete_before_entry(void *Opaque) {
  struct ThreadCall *Call = Opaque;
  void *Result = Call->Routine(Call->Argument);
  free(Call);
  pthread_mutex_lock(&Lock);
  Done = true;
  pthread_cond_signal(&Ready);
  pthread_mutex_unlock(&Lock);
  return Result;
}

int __wrap_pthread_create(pthread_t *Thread, const pthread_attr_t *Attributes,
                          void *(*Routine)(void *), void *Argument) {
  if (!Delay)
    return __real_pthread_create(Thread, Attributes, Routine, Argument);
  struct ThreadCall *Call = malloc(sizeof(*Call));
  if (!Call)
    return ENOMEM;
  *Call = (struct ThreadCall){Routine, Argument};
  pthread_mutex_lock(&Lock);
  Done = false;
  int Status =
      __real_pthread_create(Thread, Attributes, complete_before_entry, Call);
  if (Status) {
    free(Call);
    pthread_mutex_unlock(&Lock);
    return Status;
  }
  // The real timer must finish before vm_start can reset native exit state.
  // No engine-private state is read or changed by this scheduling control.
  while (!Done)
    pthread_cond_wait(&Ready, &Lock);
  pthread_mutex_unlock(&Lock);
  return Status;
}

static void deadline_before_entry(uc_arch Arch, uc_mode Mode, int Register,
                                  const uint8_t *Bytes, size_t Size) {
  uc_engine *UC = NULL;
  uint64_t Counter = 0;
  size_t TimedOut = 0;
  OK(uc_open(Arch, Mode, &UC));
  OK(uc_mem_map(UC, Code, PageBytes, UC_PROT_ALL));
  OK(uc_mem_write(UC, Code, Bytes, Size));
  OK(uc_reg_write(UC, Register, &Counter));
  Delay = true;
  OK(uc_emu_start(UC, Code, UINT64_MAX, ShortTimeout, 0));
  Delay = false;
  OK(uc_query(UC, UC_QUERY_TIMEOUT, &TimedOut));
  TEST_CHECK(TimedOut);
  OK(uc_reg_read(UC, Register, &Counter));
  TEST_CHECK(Counter == 0);
  // A subsequent run consumes its own budget and makes exactly one effect.
  OK(uc_emu_start(UC, Code, UINT64_MAX, Timeout, OneInstruction));
  OK(uc_query(UC, UC_QUERY_TIMEOUT, &TimedOut));
  TEST_CHECK(!TimedOut);
  OK(uc_reg_read(UC, Register, &Counter));
  TEST_CHECK(Counter == OneInstruction);
  OK(uc_close(UC));
}

#define UC_DEADLINE_CASE(Name, Arch, Mode, Register, ...)                      \
  static void Name(void) {                                                     \
    const uint8_t Bytes[] = {__VA_ARGS__};                                     \
    deadline_before_entry(Arch, Mode, Register, Bytes, sizeof(Bytes));         \
  }
#include "pre_entry_deadline.def"
#undef UC_DEADLINE_CASE

TEST_LIST = {
#define UC_DEADLINE_CASE(Name, Arch, Mode, Register, ...) {#Name, Name},
#include "pre_entry_deadline.def"
#undef UC_DEADLINE_CASE
    {NULL, NULL}};
