#
# Copyright 2016 Cray Inc. All Rights Reserved.
#
# This file is part of Cray Data Virtualization Service (DVS).
#
# DVS is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# DVS is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.
#

# Common include file for test bash scripts.
#
# test_openlog {logfile}    open a log file to record everything
# test_closelog             close any open log file
# test_set_color {0 | 1}    turn color-coding off | on (default == on)
# test_set_verbose {0..2}   set verbosity (0=log, 1=info, 2=debug)
# test_verboser             increase verbosity
# test_quieter              reduce verbosity
# test_debug {msg...}       issue a debug-level message
# test_info {msg...}        issue an info-level message
# test_log {msg...}         issue a log-level message
# test_err {msg...}         issue an error message, record error
# test_begin {name}         start a nested test with specified name
# test_complete             complete the current nested test
# test_suite_begin {name}   start a test suite
# test_suite_complete       complete a test suite

_logfile=''
_verbose=1
_color=1
_suite='all tests'
_depth=0
_failcnt=0
_starttime=''

declare -a _names
declare -ai _times
declare -ai _errors

function _reset_suite
{
    unset _names
    unset _times
    unset _errors
    _depth=0
    _failcnt=0
}

function _initstarttime
{
    force=$1
    if [[ -n "$force" || -z "$_starttime" ]]; then
        _starttime=$(( $(date +%s%N) / 1000 ))
    fi
}

function _elapsed
{
    since=$1
    _initstarttime
    if [[ -z "$since" ]]; then
        since=$_starttime
    fi
    echo $(( ($(date +%s%N) / 1000) - $since ))
}

function _blk
{
    echo -e "\033[39m"
}
function _grn
{
    echo -e "\033[32m"
}
function _red
{
    echo -e "\033[31m"
}

function _passfailtxt
{
    errcnt=$1
    color=$2
    if [[ $errcnt -lt 0 ]]; then
        return
    fi
    if [[ $color -ne 0 && $_color -ne 0 ]]; then
        if [[ $errcnt -gt 0 ]]; then
            echo "$(_red)[FAIL] $(_blk)"
        else
            echo "$(_grn)[pass] $(_blk)"
        fi
    else
        if [[ $errcnt -gt 0 ]]; then
            echo "[FAIL] "
        else
            echo "[pass] "
        fi
    fi
}

function _errortxt
{
    iserr=$1
    color=$2
    if [[ $iserr -eq 0 ]]; then
        return
    fi
    if [[ $color -ne 0 && $_color -ne 0 ]]; then
        echo "$(_red)ERROR $(_blk)"
    else
        echo "ERROR "
    fi
}

function test_openlog
{
    _logfile="$1"
}

function test_closelog
{
    _logfile=''
}

function test_set_suite_name
{
    _suite="$@"
    if [[ -z "$_suite" ]]; then
        _suite="all tests"
    fi
}

function test_set_fail_count
{
    _failcnt="$1"
    if [[ -z "$_failcnt" ]]; then
        _failcnt=0
    fi
}

function test_set_color
{
    old=$_color;
    _color=$1
    return $old
}

function test_set_verbose
{
    old=$_verbose
    case "$1" in
    debug)  _verbose=2;;
    info)   _verbose=1;;
    none)   _verbose=0;;
    *)      _verbose=$1;;
    esac
    if [[ $_verbose -gt 2 ]]; then
        _verbose=2
    elif [[ $_verbose -lt 0 ]]; then
        _verbose=0
    fi
    return $old
}

function test_verboser
{
    if [[ $_verbose -lt 2 ]]; then
        _verbose=$(($_verbose + 1))
    fi
}

function test_quieter
{
    if [[ $_verbose -gt 0 ]]; then
        _verbose=$(($_verbose - 1))
    fi
}

function _vlog2
{
    errcnt=$1
    thresh=$2
    shift 2
    tstamp=$(_elapsed)
    tstamp=$(printf "%4d.%06d" $(( $tstamp / 1000000 )) $(( $tstamp % 1000000 )))
    prefix=''
    for (( i=0; i<${#_names[*]}; i++ )); do
        prefix="$prefix${_names[$i]}:"
    done
    if [[ -n "$prefix" ]]; then
        prefix="$prefix "
    fi
    if [[ $thresh -lt 0 || $thresh -gt 2 ]]; then
        echo "$prefix$(_passfailtxt $errcnt 1)$(_errortxt 1 1)$@" >&2
    elif [[ $_verbose -ge $thresh ]]; then
        echo "$prefix$(_passfailtxt $errcnt 1)$(_errortxt 0 1)$@"
    fi
    if [[ -n "$_logfile" ]]; then
        if [[ $thresh -lt 0 || $thresh -gt 2 ]]; then
            echo "$tstamp $prefix$(_passfailtxt $errcnt 0)$(_errortxt 1 0)$@" >>$_logfile
        elif [[ $_verbose -ge $thresh || $thresh -le 1 ]]; then
            echo "$tstamp $prefix$(_passfailtxt $errcnt 0)$(_errortxt 0 0)$@" >>$_logfile
        fi
    fi
}

function test_debug
{
    _vlog2 -1 2 $@
}

function test_info
{
    _vlog2 -1 1 $@
}

function test_log
{
    _vlog2 -1 0 $@
}

function test_err
{
    _vlog2 -1 -1 $@
    _failcnt=$(($_failcnt + 1))
    d=$(($_depth-1))
    if [[ $d -ge 0 ]]; then
        _errors[$d]=$((${_errors[$d]}+1))
    fi
}

function test_begin
{
    _initstarttime
    name="$@"
    if [[ -z "$name" ]]; then
        name="test"
    fi
    _names[$_depth]=$name
    _errors[$_depth]=0
    _times[$_depth]=$(( $(date +%s%N) / 1000 ))
    _depth=$(($_depth+1))
    _vlog2 -1 1 "started"
}

function test_complete
{
    d=$(($_depth-1))
    if [[ $d -lt 0 ]]; then
        test_err "Script error, test_complete called without matching test_begin"
        return 1
    fi
    errs=${_errors[$d]}
    time=$(_elapsed ${_times[$d]})
    time=$(printf "%d.%06d" $(( $time / 1000000 )) $(( $time % 1000000 )))
    _vlog2 $errs 1 "completed with $errs errors ($time sec)"
    _depth=$d
    unset _names[$_depth]
    unset _times[$_depth]
    unset _errors[$_depth]
    if [[ $errs -gt 0 ]]; then
        d=$(($_depth-1))
        if [[ $d -ge 0 ]]; then
            _errors[$d]=$((${_errors[$d]} + $errs))
        fi
    fi
    if [[ $errs -gt 0 ]]; then
        return 1
    fi
    return 0
}

function test_suite_begin
{
    _initstarttime 1
    test_set_suite_name "$@"
    unset _names
    unset _times
    unset _errors
    _failcnt=0
    _depth=0
    _vlog2 -1 0
    _vlog2 -1 0 "'$_suite' started"
}

function test_suite_complete
{
    time=$(_elapsed)
    time=$(printf "%d.%06d" $(( $time / 1000000 )) $(( $time % 1000000 )))
    errs=$_failcnt
    unset _names
    unset _times
    unset _errors
    _failcnt=0
    _depth=0
    _vlog2 $errs 0 "'$_suite' completed with $errs errors ($time sec)"
    test_set_suite_name
    if [[ $errs -gt 0 ]]; then
        return 1
    fi
    return 0
}

function _empty_check
{
    id=$1
    fail=$2
    shift 2
    txt="$@"
    if [[ -n "$txt" ]]; then
        echo "Expected empty string" >&2
        fail=$(($fail + 1))
    fi
    echo $fail
}

function _nempt_check
{
    id=$1
    fail=$2
    shift 2
    txt="$@"
    if [[ -z "$txt" ]]; then
        echo "Expected non-empty string" >&2
        fail=$(($fail + 1))
    fi
    echo $fail
}

function _check_complete_return
{
    err=$1
    exp=$2
    fail=$3
    if [[ $err -ne $exp ]]; then
        echo "Unexpected test_complete result $err != $exp" >&2
        fail=$(($fail + 1))
    fi
    echo $fail
}

function _count_log_lines
{
    file=$1
    exp=$2
    fail=$3
    x=$(cat $file|wc -l)
    if [[ $exp -lt 0 ]]; then
        echo "Log file contents:" >&2
        cat $file | sed 's/^/>>/' >&2
    elif [[ $x -ne $exp ]]; then
        echo "Log file line count not expected, $x != $exp" >&2
        cat $file | sed 's/^/>>/' >&2
        fail=$(($fail + 1))
    fi
    rm -f $file
    echo $fail
}

function selftest_common_bash
{
    fail=0

    # Test verbosity levels
    test_set_verbose none
    fail=$(_empty_check v0d  $fail "$(test_debug debugmessage)")
    fail=$(_empty_check v0i  $fail "$(test_info infomessage)")
    fail=$(_nempt_check v0l  $fail "$(test_log logmessage)")
    fail=$(_empty_check v0e0 $fail "$(test_err errormessage 2>/dev/null)")
    fail=$(_nempt_check v0e1 $fail "$(test_err errormessage 2>&1)")

    test_set_verbose info
    fail=$(_empty_check v1d  $fail "$(test_debug debugmessage)")
    fail=$(_nempt_check v1i  $fail "$(test_info infomessage)")
    fail=$(_nempt_check v1l  $fail "$(test_log logmessage)")
    fail=$(_empty_check v1e0 $fail "$(test_err errormessage 2>/dev/null)")
    fail=$(_nempt_check v1e1 $fail "$(test_err errormessage 2>&1)")

    test_set_verbose debug
    fail=$(_nempt_check v2d  $fail "$(test_debug debugmessage)")
    fail=$(_nempt_check v2i  $fail "$(test_info infomessage)")
    fail=$(_nempt_check v2l  $fail "$(test_log logmessage)")
    fail=$(_empty_check v2e0 $fail "$(test_err errormessage 2>/dev/null)")
    fail=$(_nempt_check v2e1 $fail "$(test_err errormessage 2>&1)")

    # These are most useful if examined visually
    test_set_verbose info

    test_begin level0
    test_complete
    fail=$(_check_complete_return $? 0 $fail)

    test_suite_begin "Simple test"
    test_begin level1
    test_complete
    fail=$(_check_complete_return $? 0 $fail)
    test_suite_complete
    fail=$(_check_complete_return $? 0 $fail)

    test_suite_begin "Test with sublevel"
    test_begin level21
    test_begin level22
    test_complete
    fail=$(_check_complete_return $? 0 $fail)
    test_complete
    fail=$(_check_complete_return $? 0 $fail)
    test_suite_complete
    fail=$(_check_complete_return $? 0 $fail)

    test_suite_begin "Test with sublevel and failure"
    test_begin level31
    test_begin level32a
    test_complete
    fail=$(_check_complete_return $? 0 $fail)
    test_begin level32b
    test_err "oops!"
    test_complete
    fail=$(_check_complete_return $? 1 $fail)
    test_complete
    fail=$(_check_complete_return $? 1 $fail)
    test_suite_complete
    fail=$(_check_complete_return $? 1 $fail)

    test_set_verbose none

    test_suite_begin "Test with sublevel and success, quiet"
    test_begin level41
    test_begin level42a
    test_complete
    fail=$(_check_complete_return $? 0 $fail)
    test_begin level42b
    test_complete
    fail=$(_check_complete_return $? 0 $fail)
    test_complete
    fail=$(_check_complete_return $? 0 $fail)
    test_suite_complete
    fail=$(_check_complete_return $? 0 $fail)

    test_suite_begin "Test with sublevel and failure, quiet"
    test_begin
    test_begin level52a
    test_complete
    fail=$(_check_complete_return $? 0 $fail)
    test_begin level52b
    test_err "oops!"
    test_complete
    fail=$(_check_complete_return $? 1 $fail)
    test_complete
    fail=$(_check_complete_return $? 1 $fail)
    test_suite_complete
    fail=$(_check_complete_return $? 1 $fail)

    test_log
    test_log "Test stand-alone test_complete"
    test_complete
    fail=$(_check_complete_return $? 1 $fail)
    test_suite_complete
    fail=$(_check_complete_return $? 1 $fail)
    test_suite_complete
    fail=$(_check_complete_return $? 0 $fail)

    # Test logging
    file=/tmp/test_common.log
    rm -f $file
    test_log
	test_log "Test stand-alone log file, verbosity 0"
    test_set_verbose 0
    test_openlog $file
    test_debug "debug message"
    test_info "info message"
    test_log "log message"
    test_err "error message"
    test_closelog
    fail=$(_count_log_lines $file 3 $fail)

    test_log
	test_log "Test stand-alone log file, verbosity 1"
    test_set_verbose 1
    test_openlog $file
    test_debug "debug message"
    test_info "info message"
    test_log "log message"
    test_err "error message"
    test_closelog
    fail=$(_count_log_lines $file 3 $fail)

    test_log
	test_log "Test stand-alone log file, verbosity 2"
    test_set_verbose 2
    test_openlog $file
    test_debug "debug message"
    test_info "info message"
    test_log "log message"
    test_err "error message"
    test_closelog
    fail=$(_count_log_lines $file 4 $fail)

    test_log
    test_log "Test log file format, verbosity 2"
    test_set_verbose 2
    test_openlog $file
    test_debug "debug message"
    test_info "info message"
    test_log "log message"
    test_err "error message"
    test_closelog
    fail=$(_count_log_lines $file -1 $fail)

    test_log
    test_log "Sample output"
    test_set_verbose info
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

    test_log
    test_set_suite_name "common BASH logging regression"
    test_set_fail_count $fail
    test_suite_complete
}

if [[ $(basename $0) == 'test_common.sh' ]]; then
    selftest_common_bash
    exit 0
fi

