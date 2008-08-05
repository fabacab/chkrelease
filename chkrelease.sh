#!/bin/bash -
# File:        chkrelease.sh
#
# Description: Utility script to cryptographically verify the contents
#              of a filesystem against the content of a tarball. Useful
#              in quickly auditing a filesystem of a production server
#              against a release from a source code management system.
#
# Examples:    A quick way to overwrite all files that this script has
#              discovered were modified is to extract the output of the
#              command and feed these paths to `tar`, like so:
#
#                  ./chkrelease.sh /tmp/release-tarball.tar / | \
#                    awk '{ print $1 }' | \
#                      tar -C / -xvf /tmp/release-tarball.tar --files-from=-
#
#              The command expansion simply extracts the first column of output
#              produced by the script if one exists, which is the filesystem
#              paths present in the release tarball. It sends these paths to tar
#              via standard input to extract them at the same directory that we're
#              checking against which in this case is the root directory (/).
#
#              Another way to use this utility is to generate a difference listing
#              from the filesystem's contents and the release archive. To do this
#              simply redirect STDOUT to a file.
#
#                  ./chkrelease.sh /tmp/release-tarball.tar / > /tmp/deltas &
#
#              This will run as a background job. At any time, send the process ID
#              of the job a SIGHUP to see a progress report. When it's done, you can
#              then mend the filesystem deltas by feeding the deltas file to tar.
#
#                  awk '{print $1}' /tmp/deltas | \
#                      tar -C / -xvf /tmp/release-tarball.tar --files-from=-
#
#              Another use of chkrelease.sh is to generate a report that shows
#              whether or not a directory hierarchy's contents match the contents of
#              a tarfile. To do this, simply reverse the arguments to the script
#              so that the second argument is the tarfile and the first is the path
#              you want to check. This usage looks like this:
#
#                  chkrelease.sh ~/mydir ~/backup-of-mydir.tar
#
#              Used this way, both arguments are required.
#

# DEBUGGING
set -e

# TRAP SIGNALS
trap 'showTotals 1>&2' HUP # use HUP instead of INFO since INFO is not POSIX-compliant
trap 'showTotals; cleanTmpDirAndExit' INT # do showTotals when interupted by CTRL-C
trap 'cleanTmpDir' QUIT EXIT # do cleanTmpDir immediately before exiting

# FIND BINARIES
MD5UTIL=`which md5sum || which md5` # use GNU's md5sum if exists, md5 otherwise
TARUTIL=`which tar`

# INTERNAL VARIABLES
readonly PROGRAM=`basename "$0"`
readonly VERSION="0.1.3"
TMPDIR=${TMPDIR:-/tmp}
CMPDIR='.'             # the directory on the filesystem to compare the tarball against
SHOWTOTALS=0           # whether or not to print the totals at the end
DONTCLEAN=0            # whether or not to run cleanTmpDir
SHOWPROGRESS=0         # whether or not to showTotals during operation

# GATHER PARAMETERS
# RETURN VALUES/EXIT STATUS CODES
# a return value between 1 and 125 inclusive indicates that a delta exists on the filesystem
# and doubles as a report of how many files have been modified
# (up to the limit defined by POSIX of 125, of course), which implies 0 means no delta
# while higher-numbered values indicate some abnormal process completion (up to the max of 255)
readonly E_BAD_OPTION=252
readonly E_MISSING_PARAM=253
readonly E_BAD_TARBALL=254
readonly E_UNKNOWN=255

# UTILITY FUNCTIONS
function cleanTmpDir () {
    if [ $DONTCLEAN -eq 1 -o ! -f "$TMPDIR/$PROGRAM.out.$$" ]; then
        return # We won't clean up if told not to or don't know what to clean.
    fi

    echo "Please wait while I clean the \$TMPDIR..." 1>&2

    # remove directories recursively
    grep '/' "$TMPDIR/$PROGRAM.out.$$" |
      sed -e 's/^\.\///' |
        cut -d '/' -f 1 |
          uniq |
    while read dir_to_rm; do
        rm -rf "$TMPDIR/$dir_to_rm"
    done

    # remove any top-level files
    grep -v '/' "$TMPDIR/$PROGRAM.out.$$" |
    while read file_to_rm; do
        rm -f "$TMPDIR/$file_to_rm"
    done

    # remove the temporary output file
    rm -f "$TMPDIR/$PROGRAM.out.$$"
}

function cleanTmpDirAndExit () {
    cleanTmpDir
    exit ${1:-$num_modified}
}

function getHashFromUtil () {
    case `basename $MD5UTIL` in
        'md5sum' )
            getHashFromUtil_md5sum $@
            ;;
        'md5' )
            getHashFromUtil_md5 $@
            ;;
    esac
}

function getHashFromUtil_md5 () {
    # we use the fourth position parameter ($4) because that's the default
    # space-separated parameter where `md5` returns a hash for us
    echo ${4:(-32)} # take the last 32 characters, since md5 hashes are always 32 bytes
}

function getHashFromUtil_md5sum () {
    echo `echo "$1" | cut -d ' ' -f 1`
}

function showTotals () {
    echo
    echo "Total number of files to audit: $num_total_files"
    echo "Total number of files audited:  $num_audited"
    echo "Total number of files modified: $num_modified"
    echo "Total number of files skipped:  $num_skipped"
}

function usage () {
    echo "Usage is as follows:"
    echo "$PROGRAM <--version|-v>"
    echo
    echo "    Prints the program version number on a line by itself and exits."
    echo
    echo "$PROGRAM <--help|--usage|-?>"
    echo
    echo "    Prints this usage output and exits."
    echo
    echo "$PROGRAM [--count|-c] [--messy|-m] [--progress|-p] <release_tarball> [root_of_directory_to_audit]"
    echo
    echo "    <release_tarball> is the tar file to compare [root_of_directory_to_audit] against."
    echo
    echo "    [root_of_directory_to_audit] defaults to '.' (current directory) if not specified."
    echo
    echo "    If '--count' or '-c' is specified, a summary will be printed when it is done."
    echo
    echo "    If '--messy' or '-m' is specified, $PROGRAM will not remove files from the"
    echo "    temporary directory (\$TMPDIR) that it creates when it is done running."
    echo "    Useful for examining files after $PROGRAM has run."
    echo
    echo "    If '--progress' or '-p' is specified, $PROGRAM will display a progress report"
    echo "    on STDERR during operation. Useful if you are bored and want something to watch."
    echo "    Alternatively, while $PROGRAM is running in the background, send it a SIGHUP to"
    echo "    produce the same effect. If set, '--count' is automatically assumed, as well."
    echo
    echo "$PROGRAM [--count|-c] [--messy|-m] [--progress|-p] <directory_root_to_audit> <release_tarfile>"
    echo
    echo "    Same as above, except this time the comparison will check the tarfile against the"
    echo "    filesystem instead of the othe way around. This will, for instance, show you a report of"
    echo "    files that exist on the filesystem but do not exist in the tarfile."
}

function usageAndExit () {
    usage
    exit ${1:-255}
}

function version () {
    echo "$PROGRAM version $VERSION"
}

function versionAndExit () {
    version
    exit ${1:-255}
}

# Process command-line arguments.
while test $# -gt 0; do
    case $1 in
        --count | -c )
            shift
            SHOWTOTALS=1
            ;;

        --messy | -m )
            shift
            DONTCLEAN=1
            ;;

        --progress | -p )
            shift
            SHOWPROGRESS=1
            SHOWTOTALS=1 # if asked for progress, report at end, too
            ;;

        --version | -v )
            versionAndExit 0
            ;;

        -? | --help | --usage )
            usageAndExit 0
            ;;

        -* )
            echo "Unrecognized option: $1" 1>&2
            usageAndExit $E_BAD_OPTION
            ;;

        * )
            break;
            ;;
    esac
done

# Validate our parameters and determine the operating mode based on them
if [ "$1" == '' ]; then
    echo "$PROGRAM: missing parameter" 1>&2
    usageAndExit $E_MISSING_PARAM
elif [ -f "$1" -a -r "$1" ]; then
    TARBALL="$1"
    # Get our comparison directory
    if [ "$2" != '' ]; then
        CMPDIR="$2"
        if [ ! -d $CMPDIR -o ! -r $CMPDIR ]; then
            echo "$PROGRAM: $CMPDIR is not a readable directory" 1>&2
            usageAndExit $E_BAD_OPTION
        fi
    fi
elif [ -d "$1" -a -r "$1" ]; then
    CMPDIR="$1"
    if [ "$2" == '' -o ! -r "$2" -o ! -f "$2" ]; then
        echo "$PROGRAM: No readable tarfile provided"
        usageAndExit $E_BAD_TARBALL
    else
        TARBALL="$2"
    fi
else
    echo "$PROGRAM: $1 is not a readable file or directory" 1>&2
    usageAndExit $E_BAD_OPTION
fi

"$TARUTIL" -tf "$TARBALL" | grep -v '/$' > "$TMPDIR/$PROGRAM.out.$$"

num_total_files=`grep -v '/$' "$TMPDIR/$PROGRAM.out.$$" | wc -l | awk '{print $1}'`
num_skipped=0  # count of non-normal files skipped
num_audited=0
num_modified=0 # this also becomes the exit value
while read file; do
    num_audited=`expr $num_audited + 1`
    rel_hash= # the released file's hash
    old_hash= # the filesystem file's hash

    "$TARUTIL" -C "$TMPDIR" -xf "$TARBALL" "$file"

    if [ -L "$file" ]; then # always echo symbolic links so their are untarred
        echo "$file is a symbolic link, skipping"
        num_skipped=`expr $num_skipped + 1`
        continue
    fi

    rel_hash=$(getHashFromUtil "$("$MD5UTIL" "$TMPDIR/$file")")
    if [ -f "$CMPDIR/$file" ]; then
        old_hash=$(getHashFromUtil "$("$MD5UTIL" "$CMPDIR/$file")")
    fi

    if [ "$old_hash" != "$rel_hash" ]; then
        echo "$file does not match $CMPDIR/$file"
        num_modified=`expr $num_modified + 1`
    fi

    if [ $SHOWPROGRESS -eq 1 -a `expr $num_audited % 10` -eq 0 ]; then
        clear 1>&2      # clear standard error only
        showTotals 1>&2 # because we're only outputting there
    fi
done < "$TMPDIR/$PROGRAM.out.$$"

test $SHOWTOTALS -eq 1 && showTotals 1>&2

# limit exit status to common Unix practice
if [ $num_modified -lt 126 ]; then
    exit $num_modified
else
    exit 125
fi
