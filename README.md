# PasswordManager
A Command Line Password Manager Utility written in c++ with sqlite3 database

Master password and PRIVATE_KEY
<pre>
Master Password: password
PRIVATE_KEY: (you can enter anything for the fist time, but have to remember that, coz you have to use  the same key everytime, otherwise your password will not be decrypted.
</pre>

Step 1: Get the source code
<pre>
 git clone https://github.com/rohitkrtiwari/PasswordManager.git
</pre>

Step 2: Compile the program
<pre>
 c++ .\PasswordManager.cpp .\sha256\sha256.cpp .\sqlite3.o -o PasswordManager.exe  
</pre>

<img src="images/compile.png">

Step 3: Run the executable
<pre>
 ./PasswordManager.exe
</pre>



<br><br>
<code>
**flower.jpg is the file where your passwords are stored, keep it safe and secure.**
</code>


<br><br>

## Generate Password : >> 1
<img src="images/Generate%20and%20Add.png">
<br><br>

## Add New Password : >> 2
<img src="images/add_new.png">
<br><br>

## Fetch a Saved Password : >> 3
<img src="images/get_password.png">
<br><br>

## List all Records : >> 4
<img src="images/List%20all%20Passwords.png">
<br><br>

## Delete a Password : >> 5
<img src="images/Delete_password.png">
<br><br>

## Clear all Passwords : >> 6
<img src="images/clear_all.png">
