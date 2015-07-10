# Syntax Highlighting for packetdrill Scripts

## BBEdit
The file packetdrill.plist has to be copied into ~/Library/Application Support/BBEdit/Language Modules/.
The extension .pkt for packetdrill scripts is recognized. Keywords and Predefined Names
are colored. Numbers are colored from BBEdit 11.0 onwards.

## Emacs
Install packetdrill.el.

## vim
For installation the directories ~/.vim, ~/.vim/ftdetect and ~/.vim/syntax must exist.
If they they don't exist, create them.
Then create a file ~/.vim/ftdetect/packetdrill.vim with the contents:
au BufRead,BufNewFile *.pkt set filetype=packetdrill
Finally copy the provided file packetdrill.vim to ~/.vim/syntax/packetdrill.vim
