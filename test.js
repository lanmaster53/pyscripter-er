/*

Serve this file and load it through Burp to test.
Burp should find 23/27 links.
4/27 (*) are invalid test cases.

    "http://example.com"
    "smb://example.com"
    "https://www.example.co.us"
    "/path/to/file"
    "../path/to/file"
    "./path/to/file"
    "/user/create.action?user=Test"
    "/api/create.php?user=test&pass=test#home"
  * "/wrong/file/test<>b"
    "api/create.php"
    "api/create.php?user=test"
    "api/create.php?user=test&pass=test"
    "api/create.php?user=test#home"
    "user/create.action?user=Test"
  * "user/create.notaext?user=Test"
    "/path/to/file"
    "../path/to/file"
    "./path/to/file"
  * "/wrong/file/test<>b"
    "test_1.json"
    "test2.aspx?arg1=tmp1+tmp2&arg2=tmp3"
    "addUser.action"
    "main.js"
    "index.html"
    "robots.txt"
    "users.xml"
  * "UserModel.name"

*/
