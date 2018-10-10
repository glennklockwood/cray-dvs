Unit Test Framework
===================

This provides a simple framework for writing unit tests in either C, or in
BASH. Apart from syntax differences between the languages, the calls are
all the same.

Here is the typical structure of a simple regression test, using this
framework:

```bash
  test_set_verbose 1
  test_set_color 1
  test_openlog /tmp/mytestsuite.log
  test_suite_begin My Test Suite
    test_begin Test1
      test_log This message will always be logged
      # perform some tests
      test_info This message is informative, displayed at verbosity level 1
      test_debug This message is for debugging, displayed at verbosity level 2
      test_err Oops! This test had an error!
    test_complete
    test_begin Test2
      # perform more tests
    test_complete
  test_suite_complete
```

The big advantage of this framework is that it allows tests to be nested.
It's typical in regression testing to perform the same sequence of tests
under a variety of conditions. So it might look like this:

```bash
  file=/tmp/mylogfile.txt
  test_log
  test_log "Sample output"
  test_set_verbose 1
  test_openlog $file
  test_suite_begin Regression Suite
    for condition in a b; do
      test_begin Condition $condition
        test_begin Test1
	  test_log running...
        test_complete
        test_begin Test2
	  test_log running...
        test_complete
      test_complete
    done
  test_suite_complete
  test_closelog
  test_log
  test_log "Sample log contents"
  cat $file
  rm -f $file
```

Sample output

'Regression Suite' started
Condition a: started
Condition a:Test1: started
Condition a:Test1: running...
Condition a:Test1: [pass] completed with 0 errors (0.011123 sec)
Condition a:Test2: started
Condition a:Test2: running...
Condition a:Test2: [pass] completed with 0 errors (0.010011 sec)
Condition a: [pass] completed with 0 errors (0.040347 sec)
Condition b: started
Condition b:Test1: started
Condition b:Test1: running...
Condition b:Test1: [pass] completed with 0 errors (0.009529 sec)
Condition b:Test2: started
Condition b:Test2: running...
Condition b:Test2: [pass] completed with 0 errors (0.009566 sec)
Condition b: [pass] completed with 0 errors (0.038277 sec)
[pass] 'Regression Suite' completed with 0 errors (0.101242 sec)

Sample log contents
   0.001241
   0.005550 'Regression Suite' started
   0.011058 Condition a: started
   0.016350 Condition a:Test1: started
   0.020554 Condition a:Test1: running...
   0.028221 Condition a:Test1: [pass] completed with 0 errors (0.011123 sec)
   0.034266 Condition a:Test2: started
   0.038644 Condition a:Test2: running...
   0.044895 Condition a:Test2: [pass] completed with 0 errors (0.010011 sec)
   0.051827 Condition a: [pass] completed with 0 errors (0.040347 sec)
   0.057513 Condition b: started
   0.063186 Condition b:Test1: started
   0.067358 Condition b:Test1: running...
   0.073334 Condition b:Test1: [pass] completed with 0 errors (0.009529 sec)
   0.079415 Condition b:Test2: started
   0.083466 Condition b:Test2: running...
   0.089576 Condition b:Test2: [pass] completed with 0 errors (0.009566 sec)
   0.096414 Condition b: [pass] completed with 0 errors (0.038277 sec)
   0.103143 [pass] 'Regression Suite' completed with 0 errors (0.101242 sec)


Function Calls
==============

test_openlog
: Open a log file for logging test operations

test_closelog
: Close an open log file

test_set_suite_name
: Change the test suite name

test_set_fail_count
: Change the test suite failure count

test_set_color
: Enable (1) or disable (0) color codes in stdout

test_set_verbose
: Set verbosity level (0, 1, 2)

test_debug
: Emit a debug message (level 2)

test_info
: Emit an informational message (level 1)

test_log
: Emit a log message (level 0)

test_err
: Emit an error message, count as a failure

test_begin
: Begin a named test

test_complete
: Complete a named test

test_suite_begin
: Begin a named test suite

test_suite_complete
: Complete a named test suite
