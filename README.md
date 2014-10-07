## Notelock: A simple terminal note encryption service

#### Use: `notelock [OPTION]... [NOTEBOOK] [message]`

Notelock stores notes in "notebooks." Each notebook has entries stored in
chronological order. To add an entry to a type `notelock [book name] [message]`,
and it will be appended to the notebook with the notebook's password, without
the need for password re-entry. If [book name] does not exist, then the
user will be prompted to create it [y/n] and asked for an encryption password
(twice). `notelock -f [book name] [filename]` will accept the contents of a
file. It will not check for the type of data in the file, so be careful.

To read from a book, put `notelock -r [book name]`. This will prompt the user
for the book's password, and print entries from the book for the last day. The
`-F` option will start looking from the [F]ront of the file, so the first entry
will be printed last (and be visible first). The `-a` option prints all entries.

There is no way to delete entries, and currently no way to edit them.

#### Features to add:
- Editing: It seems reasonable to edit entries, at least by appending. This
  will mean some way to access individual notes.
  * Maybe the -r command will let the user scroll through notes using
    up/down, and whichever note s/he is currently on can be edited by
    hitting Enter?

- Tags: Each note can be stored with a #tag, and books can be searched by
  tag.

- Range search: Notes can be filtered by range, with 'notelock --range
  [start date] [end date]'. Or maybe 'notelock --start [start date] --end
  [end date]', to allow open-ended ranges.

- Summary: `notelock -l [book name]` will list all the days for which there
  are entries, along with the number of entries for each day.


#### Implementation:
- Each day stored in a file, YYYY-MM-DD
- Each entry encrypted seperately, preceeded by auth signiture
- Each notebook stored in a directory
- Text stored as unicode
