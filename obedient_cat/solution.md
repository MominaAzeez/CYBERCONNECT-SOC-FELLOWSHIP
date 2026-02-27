Challenge Name: Obedient Cat

Description: This file has a flag in plain sight (aka "in-the-clear"). The link is provided to access the file.

Solution
Method 1: Downloading the File
By clicking the link [flag], the file is downloaded.
Now check the contents of the file by opening it in Notepad or any text editor.
The flag is literally written in plain sight!
Copy the line and submit it as the solution.

Method 2: By wget and cat Commands
Copy the link of the file and download the file using the wget command:

text
wget <file-link>
(You can paste the link you copied in the webshell by right-clicking and pasting it.)
The file was downloaded named as flag.
We can see the content of the file by using the cat command:

text
cat flag
Flag: picoCTF{s4n1ty_v3r1f13d_9b8fa0bc}
