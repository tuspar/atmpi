from tkinter import *
from tkinter import messagebox
from ttkthemes import themed_tk as tk
from tkinter import ttk

from db import db
from time import gmtime
from PIL import ImageTk,Image 
import time, pyotp, qrcode, os

#Logs In and Opens Home Window
def login():
    def home():
        #Hide Login Page
        login_window.withdraw()

        #Create Window Object
        home = Toplevel()
        home.title('Home')
        home.geometry('400x200')
        
        #Button Params
        w = 20
        home.rowconfigure((0,4), weight=1)
        home.columnconfigure((0,1), weight=1) 

        #Setup Buttons
        ttk.Button(home, text='Cash Deposit', width=w, command= lambda: depwith("Deposit")).grid(row=0, column=0, columnspan=1, sticky='EWNS')
        ttk.Button(home, text='Cash Withdraw', width=w, command= lambda: depwith("Withdraw")).grid(row=1, column=0, columnspan=1, sticky='EWNS')
        ttk.Button(home, text='Transfer Money', width=w, command=transfer).grid(row=2, column=0, columnspan=1, sticky='EWNS')
        ttk.Button(home, text='Change Two Factor', width=w, command=twoFA).grid(row=3, column=0, columnspan=1, sticky='EWNS')
        ttk.Button(home, text='Exit', width=w*2, command= lambda: logout(home)).grid(row=4, column=0, columnspan=2, sticky='EWNS')
        
        ttk.Button(home, text='Change Pin', width=w, command=changepin).grid(row=0, column=1, columnspan=1, sticky='EWNS')
        ttk.Button(home, text='View Transactions', width=w, command=transactions).grid(row=1, column=1, columnspan=1, sticky='EWNS')
        ttk.Button(home, text='View Balance', width=w, command=balance).grid(row=2, column=1, columnspan=1, sticky='EWNS')
        ttk.Button(home, text='Pay Bill', width=w, command=bill).grid(row=3, column=1, columnspan=1, sticky='EWNS')
        

    def verify(window):
        window.destroy()
        if totp.verify(code.get()):               
            home()
        else:
            messagebox.showerror(title="Warning", message="Wrong OTP")
            db.deauth()
            login_window.deiconify()
            login_window.update()

    username = username_text.get()
    password = password_text.get()

    username_text.set("")
    password_text.set("")

    if db.login(username, password):
        if db.user['2fa_code'] != '0':
            totp = pyotp.TOTP(db.user['2fa_code'])

            twoFac = Toplevel()
            twoFac.title('Two Factor Authentication')
            twoFac.geometry('450x200')
            
            ttk.Label(twoFac, text=("Enter OTP"), font=('bold', 30)).pack(pady=(20, 20))
            code = StringVar()
            ttk.Entry(twoFac, textvariable=code, font=(35), justify='center').pack(pady=(0, 10))
            ttk.Button(twoFac, text='Enter', width=20, command=lambda: verify(twoFac)).pack(pady=(0, 10))
        else:
            home() 
    else:
        messagebox.showerror(title="Warning", message="Wrong Card Number/PIN")
        
#Deposit/Withdrawal Windows
def depwith(mode):
    def execute():
        if mode == "Deposit":
            amount = amount_text.get()
        else: 
            amount = ("-" + amount_text.get())

        package = db.modbal(amount,  mode + " AED " + amount_text.get() + " at " + gettime())
        if(package['status'] == "s"):
            messagebox.showinfo(title="Alert", message="Updated Balance: " + format(package['balance']))
        else:
            messagebox.showerror(title="Alert", message=mode + " Failed")
        depwith.destroy()

    depwith = Toplevel()
    depwith.title(mode + " Cash")
    depwith.geometry('450x250')

    ttk.Label(depwith, text=("Cash " + mode), font=('bold', 30)).pack(pady=(20, 20))
    ttk.Label(depwith, text=("Current Balance: " + format(db.user['balance'])), font=(35)).pack(pady=(0, 10))
    ttk.Label(depwith, text="Amount", font=(35)).pack(pady=(10, 10))

    amount_text = StringVar()
    ttk.Entry(depwith, textvariable=amount_text, font=(35), justify='center').pack(pady=(0, 10))
    ttk.Button(depwith, text=mode, width=12, command=execute).pack()

#Pay Bill Window
def bill():
    package = {}
    def getbill():
        nonlocal package
        package = db.bill(authority_text.get())
        ttk.Label(bill, text="Bill for amount " + format(package['amount']), font=(35)).pack(pady=(0, 10))
        ttk.Button(bill, text="Pay Bill", width=12, command=paybill).pack(pady=(0, 10))
    
    def paybill():
        nonlocal package
        balance = db.modbal(("-" + package['amount']), "Paid Bill for " + package['authority'] + " of AED " + package['amount'] + " at " + gettime())
        messagebox.showinfo(title="Alert", message="Paid Bill; Updated Balance: AED " + balance['balance'])
        bill.destroy()

    bill = Toplevel()
    bill.title('Pay Bills')
    bill.geometry('450x300')

    ttk.Label(bill, text=("Pay Bill"), font=('bold', 30)).pack(pady=(20, 20))
    ttk.Label(bill, text="Authority", font=(35)).pack(pady=(0, 10))

    authority_text = StringVar()
    choices = {"DEWA", "Dubai Police", "Etisalat", "Du", "RTA", "Salik"}
    authority_text.set("Select Authority")
    ttk.OptionMenu(bill, authority_text, *choices).pack(pady=(0, 10))
    
    ttk.Button(bill, text="Get Bill", width=12, command=getbill).pack(pady=(0, 10))
    
#Change Pin Window
def changepin():
    def execute():
        if(new_pin_text.get() == confirm_new_pin_text.get()):
            package = db.changepin(old_pin_text.get(), new_pin_text.get())
            if(package['status'] == "s"):
                messagebox.showinfo(title="Alert", message="Pin Changed Successfully")
                change.destroy()
            else:
                messagebox.showinfo(title="Alert", message="Old Pin is Invalid")
                old_pin_text.set("")
                new_pin_text.set("")
                confirm_new_pin_text.set("")
        else:
            messagebox.showinfo(title="Alert", message="New Pins Dont Match")
            new_pin_text.set("")
            confirm_new_pin_text.set("")
    
    change = Toplevel()
    change.title('Change Pin')
    change.geometry('450x320')

    ttk.Label(change, text=("Change PIN"), font=('bold', 30)).pack(pady=(20, 20))

    old_pin_text = StringVar()
    ttk.Label(change, text="Old Pin", font=(35)).pack(pady=(0, 10))
    ttk.Entry(change, textvariable=old_pin_text, show="*", justify='center').pack(pady=(0, 10))

    new_pin_text = StringVar()
    ttk.Label(change, text="New Pin", font=(35)).pack(pady=(0, 10))
    ttk.Entry(change, textvariable=new_pin_text, show="*", justify='center').pack(pady=(0, 10))

    confirm_new_pin_text = StringVar()
    ttk.Label(change, text="Confirm Pin", font=(35)).pack(pady=(0, 10))
    ttk.Entry(change, textvariable=confirm_new_pin_text, show="*", justify='center').pack(pady=(0, 10))

    ttk.Button(change, text='Change Pin', width=12, command=execute).pack(pady=(0, 10))

#View Transactions Window
def transactions():
    transactions = Toplevel()
    transactions.title('View Transactions')
    transactions.geometry('450x400')

    ttk.Label(transactions, text=("Transactions"), font=('bold', 30)).pack(pady=(20, 20))

    cols = ('Description')
    listBox = ttk.Treeview(transactions, columns=cols, show='headings')
    listBox.heading(cols, text=cols)
    listBox.pack(fill='x', padx=(20,20), pady=(0,20))

    transactions = db.transactions()
    for i in range(0, 20):
        if str(i) in transactions:
            listBox.insert("", "end", values=(transactions[str(i)],))
        else:
            break

#View Balance Window
def balance():
    balance = Toplevel()
    balance.title('View Balance')
    balance.geometry('450x400')

    ttk.Label(balance, text=("View Balance"), font=('bold', 30)).pack(pady=(20, 20))
    ttk.Label(balance, text="Name: " + (db.user['first_name'] + " " + db.user['last_name']), font=(40)).pack(pady=(0, 10))
    ttk.Label(balance, text="Card Number: " + (db.user['cardnum']), font=(40)).pack(pady=(0, 10))
    ttk.Label(balance, text="Balance: " + ("AED " + db.user['balance']), font=(40)).pack(pady=(0, 10))
    ttk.Label(balance, text="Type: " + (db.user['type']), font=(40)).pack(pady=(0, 10))

#Transfer Money
def transfer():
    def execute():
        package = db.modbal(amount_text.get(), "Transfered AED " + amount_text.get() + " at " + 
            gettime() + " to " + bank_text.get() + ", Account Number: " + account_number_text.get())
        if(package['status'] == "s"):
            messagebox.showinfo(title="Alert", message="Transferred; New Balance AED " + package['balance'])
        else:
            messagebox.showerror(title="Alert", message="Transfer Failed, Insufficient Funds")
        transfer.destroy()

    transfer = Toplevel()
    transfer.title('Electronic Funds Transfer')
    transfer.geometry('450x400')

    ttk.Label(transfer, text=("Transfer Credit"), font=('bold', 30)).pack(pady=(20, 20))
    ttk.Label(transfer, text="Beneficiary's Bank", font=(35)).pack(pady=(0, 10))

    bank_text = StringVar()
    choices = {"ADCB", "ADIB", "Arab Bank", "Bank of Baroda", "EIB", "Bank of Sharjah", "Citibank", 
        "Dubai Islamic Bank", "Emirates Islamic", "RAK Bank", "First Gulf Bank"}
    bank_text.set("Select Bank")
    ttk.OptionMenu(transfer, bank_text, *choices).pack(pady=(0, 10))

    account_number_text = StringVar()
    ttk.Label(transfer, text="Beneficiary's Account Number", font=(35)).pack(pady=(0, 10))
    ttk.Entry(transfer, textvariable=account_number_text, justify='center', font=(30)).pack(pady=(0, 10))

    amount_text = StringVar()
    ttk.Label(transfer, text="Transfer Amount", font=(35)).pack(pady=(0, 10))
    ttk.Entry(transfer, textvariable=amount_text, justify='center', font=(30)).pack(pady=(0, 10))

    ttk.Button(transfer, text="Transfer Funds", width=12, command=execute).pack(pady=(0, 10))

#Two Factor Change
def twoFA():
    def generate():
        nonlocal key, keyLabel, status, statusLabel
        if status == "Enabled":
            db.change2Fac('0')
            status = "Disabled"
        key = pyotp.random_base32()

        totp = pyotp.TOTP(key)
        qrcode.make(totp.provisioning_uri(name='Bank OTP')).save('temp.gif')
        
        photo = PhotoImage(file="temp.gif")      
        panel.configure(image=photo)
        panel.image = photo
        os.remove("temp.gif")

        keyLabel.configure(text='Key: ' + key)
        statusLabel.configure(text='Status: ' + status)

    def enable():
        package = db.change2Fac(key)
        if package['status'] == 's':
            messagebox.showinfo(title="Updated Key", message="Two Factor Key has been Updated")
        else:
            messagebox.showerror(title="Error", message="Unable to Update Key")
        
        twoFA.destroy()

    def disable():
        package = db.change2Fac('0')
        if package['status'] == 's':
            messagebox.showinfo(title="Updated Key", message="Two Factor Key has been Updated")
        else:
            messagebox.showerror(title="Error", message="Unable to Update Key")
        
        twoFA.destroy()

    global photo
    twoFA = Toplevel()
    twoFA.title('Change Two Factor Authentication')
    twoFA.geometry('700x750')

    ttk.Label(twoFA, text=("Change Two Factor Authentication"), font=('bold', 30)).pack(pady=(20, 20))

    if db.user['2fa_code'] == '0':
        key = pyotp.random_base32()
        status = "Disabled"
    else:
        key = db.user['2fa_code']
        status = "Enabled"
    
    totp = pyotp.TOTP(key)
    qrcode.make(totp.provisioning_uri(name='Bank ATM OTP')).save('temp.gif')
         
    photo = PhotoImage(file="temp.gif")      
    panel = Label(twoFA, image=photo)
    panel.pack(pady=(20,20))
    os.remove("temp.gif")
    
    keyLabel = ttk.Label(twoFA, text='Key: ' + key, font=(32))
    keyLabel.pack(pady=(0, 10))

    statusLabel = ttk.Label(twoFA, text='Status: ' + status, font=(32))
    statusLabel.pack(pady=(0, 10))

    ttk.Button(twoFA, text='Generate New Code', width=20, command=generate).pack(pady=(0, 10))
    ttk.Button(twoFA, text='Enable', width=20, command=enable).pack(pady=(0, 10))
    ttk.Button(twoFA, text='Disable', width=20, command=disable).pack(pady=(0, 10))

#Exit To Main Screen
def logout(home):
    home.destroy() #Close Home Screen
    login_window.update() #Open Login Screen
    login_window.deiconify()
    db.deauth() #Deauthorize Security Token

#Get Current Date and Time
def gettime():
    return str("GMT: "+time.strftime("%d %b %Y %I:%M:%S %p", time.gmtime()))

#Currency Display
def format(amount):
    return "AED " + str(f'{round(float(amount), 2):,}')

#Create Window Object 
login_window = tk.ThemedTk(theme='arc')
login_window.title('ATM')
login_window.geometry('450x300')
db = db()

ttk.Label(login_window, text='Bank ATM', font=('bold', 30)).pack(pady=(20,20))

#Setup Username Entry
username_text = StringVar()
ttk.Label(login_window, text='Card Number', font=(32)).pack(pady=(0, 10))
ttk.Entry(login_window, textvariable=username_text, font=(30), justify='center').pack(pady=(0, 10))

#Setup Password Entry
password_text = StringVar()
ttk.Label(login_window, text='Pin', font=(32)).pack(pady=(0, 10))
ttk.Entry(login_window, textvariable=password_text, show='*', font=(30), justify='center').pack(pady=(0, 10))

#Setup Login Button
ttk.Button(login_window, text='Enter', width=20, command=login).pack(pady=(0, 10))

#Ping Server
if not db.ping():
    messagebox.showerror(title="Error", message="Unable to Establish Connection!")
    exit()

#Start Main Application Loop
mainloop()