# ROSEHACK
HI!


My name is Aaryan Kumar. This is my submission for RoseHack 2024.
In this project, I have created a "stock simulation", in which one can "trade" hypothetical stocks without investing any real money to learn more about the stock market.
It is purely meant to be educational, and allows anyone to register for free.

I have specially created the UI to be extremely simplistic to allow for younger users to use it easily, which will allow them to be exposed to the principles of the stock market from a young age.

NOTICE: HOW TO RUN
The application runs on a flask server, and also uses an IEX api to gain access to live stock market info.

To setup, please open the folder in your preffered IDE and run the command:    export API_KEY=pk_e918cc49883a42febe077ee3aa6c26

After running this command, run the command:    flask run

This will show you a link in the terminal. click on this link to access the website!


ADDITIONAL INFO: IN THE CASE OF ERROR  500
If you have trouble initializing the server or face any bugs, this may be due to incorrect folder placements in your IDE, as the relative paths are hard-coded in this local version with respect to the folder the application app.py and finance.db are placed in. I have faced such issues while opening these files from a diffrent device and they can often be resolved by making sure the path to finance.db  (which is in line 26 for this version in app.py) in app.py is correctly pointing to the location of the database in your folder.

If you need any additional info or help in running the program, or wish to report a bug, please contact me at kumaraaryan711@outlook.com

HAVE FUN TRADING!  :)
