Launched the instance and found a login page. Opened Developer Tools (right-click → Inspect) and spotted a comment with garbled text: "ABGR: Wnpx - grzcbenel olcnff: hfr urnqre "K-Qri-Npprff: lrf"". Ran it through ROT13 and got: "NOTE: Jack - temporary bypass: use header "X-Dev-Access: yes"".

Went to the Network tab, tried logging in with random credentials, found the POST request and copied it as cURL. Added -H 'X-Dev-Access: yes' to the command and ran it in the webshell. Got a JSON response with the flag.

![Flag](FLAG.png)
