set targetPath to "/Users/wudazi/Beforeinstall/benchmark/sandbox_output/finder_rename"

tell application "Finder"
    if not (exists folder (POSIX file targetPath as alias)) then
        make new folder at (POSIX file "/Users/wudazi/Beforeinstall/benchmark/sandbox_output/" as alias) with properties {name:"finder_rename"}
    end if

    set targetFolder to folder (POSIX file targetPath as alias)
    set fileList to every file of targetFolder

    repeat with i from 1 to count of fileList
        set f to item i of fileList
        set name of f to "renamed_" & i & "_" & (name of f)
    end repeat
end tell
