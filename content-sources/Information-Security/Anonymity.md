## Golden Rules

The below rules apply to hackers, journalists and all those who want to hide their activities or run away from stalkers.  
**Rule 1**  
If it’s not abundantly clear by now, to be invisible online you more or less need to create a separate identity, one that is completely unrelated to you. That is the meaning of being anonymous. When you’re not being anonymous, you must also rigorously defend the separation of your life from that anonymous identity.  
**Rule 2**  
Buy a separate laptop for private activities and install a secure operating system on it (Tail OS). Don't use your private laptop at work or at home, Don't connect it to your home or work Wifi and don't ever use any of your personal internet activities on it.

You can still use your own machine but make sure to use VMware or virtual box to host the operating system from which you will conduct your activities.  
**Rule 3**  
Before you connect to any open Wifi, make sure to stay out of camera views and to change your MAC address before you connect. Below are some MAC address changers

- [macchange](https://github.com/alobbs/macchanger)
- [Technitium MAC Address Changer](https://technitium.com/tmac/index.html)  
    **Rule 4**  
    After changing your MAC, launch TOR or any of the below mentioned VPNs.  
    **Rule 5**  
    If you need to pay up for something online, either use an anonymous BitCoin wallet or buy gift cards from any store where you must exercise extreme caution because of the cameras. You should not purchase these yourself. You should hire a randomly chosen person off the street to purchase the gift cards while you wait a safe distance away.  
    If you are in the EU, you can order anonymous physical credit cards via [ViaBuy](https://publish.obsidian.md/cybersecuritynotes/viabuy.com)  
    **Rule 6**  
    Use burner phones for anonymous calls.  
    **Rule 7**  
    If you don't want to connect to open public Wifi, hire someone to go and purchase a personal hotspot that allows you to connect to the Internet using cellular data. That means you have your own local access to the Internet, so you don’t have to go through a public Wi-Fi network. Most important, you should never use a personal hotspot in a fixed location for too long when you need to maintain your anonymity.  
    **Rule 8**  
    Never turn on your personal phone or personal laptop in the same location where you turn on your anonymous laptop or burner phone or anonymous hotspot. The separation is really important. Any record that links you to your anonymous self at a later date and time negates the whole operation.  
    **Rule 9**  
    Burner phone and any refill cards must be obtained securely—i.e., purchased in cash by a third party who cannot be traced back to you. Also, once you have a burner phone, you cannot use it when you’re close to any other cellular devices you own.  
    **Rule 10**  
    When selecting VPN find one that offers 128 bit encryption and that does not store activity logs. That's the first rule of business.  
    **Rule 11**  
    `VPN then TOR or vice versa?`
- **VPN then TOR**  
    You -> VPN -> TOR -> Internet.

When using VPN with TOR, first run VPN then use it to connect to TOR. Remember VPN offers privacy and TOR offers the anonymity. Even if the VPN keeps logs of every user, they will not know even with a court order the real identity of the user in question unless you purchased the VPN with your credit card or PayPal. VPN will only know that you connected to TOR but your ISP will not know you connected to TOR.

If you choose to use TOR over a VPN, the benefits are that you would be again, hiding from your ISP the fact that you are using TOR. Also, your VPN would only be able to see that you are connecting to TOR nodes and that you are sending encrypted data. The VPN would not be able to see what data you are sending over TOR unless they decrypted it, because remember, all information relayed over TOR is encrypted.

- **TOR then VPN**  
    You -> TOR -> VPN -> Internet.  
    In this case, only your ISP will know that you connected to TOR and not your VPN. The benefits of doing that are as follows. You are more anonymous to your VPN in case they happen to keep logs, or if you do something using the VPN that you are not supposed to and a website or server grabs your VPN IP address. In the case of this happening, even if the VPN manages to keep logs of everything you do, they can only identify you as an anonymous TOR user as long as you did not purchase the service with your  
    credit card or Paypal account. If you use Bitcoin, and made sure the Bitcoin trail is not easily traceable you should be okay. Some websites block TOR users from connecting to their websites or servers, by using your VPN to appear as the exit node, you are hiding your TOR activity from the website you are visiting and hopefully bypassing their filters.

A few of the downsides of doing things this way are  
that your ISP knows you are using TOR, when and for how long. This may or may not matter to you, but it is just something to consider. Second, you will be unable to visit hidden services websites. Remember those .onion sites we talked about in the beginning? You need to be connected to the TOR network to visit those hidden service websites.  
**Rule 12**  
You never want to use nicknames or locations, or anything else that is related to yourself online when you post or create usernames. And another thing you need to adopt are new ways of conducting yourself. If you are generally a messy typer, who makes the same grammar mistakes, or the same spelling mistakes all the time, this can be used to identify you. Always proof read anything you post publicly, or privately because you still can be identified by correlating patterns of your writing style.

## Anonymity For Non Blackhat Hackers

The below sections are for those who want privacy and security for their data stored in their computers and mobile devices along with protecting their internet activity from tracking.

## Operating Systems for anonymity

#### [Tail](https://tails.net/install/index.en.html)

Tail OS has several privacy tools including the  
Tor browser. The privacy tools allow you to encrypt e mail using PGP, encrypt your USB and hard drives, and secure your messages with OTR (off-the record messaging).

##### [Whonix](https://www.whonix.org)

Whonix offers tighter security than Tail so it's useful if you are running some hidden service. It offers the below features

```
Anonymous Publishing/Anti-Censorship
Anonymous E-Mail w/Thunderbird or TorBirdy
Add proxy behind Tor (user -> Tor -> proxy)
Chat anonymously.
IP/DNS protocol leak protection.
Hide that you are using Tor
Hide the fact you are using Whonix
Mixmaster over Tor
Secure And Distributed Time Synchronization Mechanism
Security by Isolation
Send E-mail anonymously without registration
Torify any app
Torify Windows
Virtual Machine Images (VM)
VPN Support
Use Adobe Flash anonymously
Use Java/Javascript anonymously
```

## Encryption

- Complete full encryption starts by setting a BIOS password. BIOS password not only protect your OS but also prevent anyone with access to your PC from recovering the decryption keys stored in your RAM (Incase you used disk encryption)

### Disk Encryption

The best method is to dedicate a separate portable storage device for your private files and encrypt it.  
You have two options

- Encrypt the whole MicroSD or USB with your private data in it.
- Install a working OS on either a MicroSD or USB and then encrypt the whole OS with the data in it.

The below will list tools useful for disk and OS encryption

##### Linux

- [TrueCrypt](http://www.truecrypt.org/downloads)
- [CryptSetup](https://gitlab.com/cryptsetup/cryptsetup)

##### Windows

- [VeraCrypt](https://www.veracrypt.fr/code/VeraCrypt/)
- [WinMagic](https://winmagic.com/en/home/)
- [Symantec Whole PGP Encryption](https://knowledge.broadcom.com/external/article/193931)
- **BitLocker**: Not available on Home editions of Windows  
    To enable it, open File Explorer, right-click on the C drive, and scroll down to the “Turn on BitLocker”. You can set BitLocker to unlock when you power up or only when there’s a PIN or a special USB that you provide. The latter choices are much safer. You also have the option of saving the key to your Microsoft account. Don’t do that, because if you do you will have more or less given Microsoft your keys

##### MacOS

- [FileVault 2](https://support.apple.com/guide/mac-help/encrypt-mac-data-with-filevault-mh11785/mac)  
    You can enable FileVault 2 by opening System Preferences, clicking on the “Security & Privacy” icon, and switching to the FileVault tab. Again, do not save your encryption key to your Apple account. This may give Apple access to it, which they in turn could give to law enforcement. Instead choose “Create a recovery key and do not use my iCloud account,” then print out or write down the twenty-four-character key. Protect this key, as anyone who finds it could unlock your hard drive.

### File Encryption

If you are using disk encryption then this means your files are all encrypted but what if you want to store some files in the cloud as well?  
Encrypt every file before you upload it to the cloud (Google drive, Apple iCloud, Dropbox) because these companies are bound by regulations and may give others access to your data.

### Network Encryption

##### VPN

If you are going to be using a VPN for any type of freedom fighting, make sure that your VPN does not keep logs. This is actually a lot harder than you might think. Many VPN providers will claim to not keep logs of your activity in order to gain you as a customer, because they have to compete with the other providers out there. Customers are going to trend towards providers who offer no identifying data retention. Unfortunately, this claim of theirs is not always the real case. When it comes down to it, no VPN provider is going to risk jail to protect a $20 a month subscriber. No matter how tough they sound, no matter how much they claim to care about protecting their customers.

Additionally, use VPNs to implement OpenVPN protocol over PPTP because the latter uses weaker encryption 128-bit versus 160-bit to 256-bit for  
OpenVPN

Always use layers of proxies and VPNs. Preferably TOR can be part of your protection layer. Example is using OpenVPN + TOR.

###### TOR

When you use TOR, the direct line between you and your target website is obscured by additional nodes, and every ten seconds the chain of nodes connecting you to whatever site you are looking at changes without disruption to you. The various nodes that connect you to a site are like layers within an onion. In other words, if someone were to backtrack from the destination website and try to find you, they’d be unable to because the path would be constantly changing. Unless your entry point and your exit point become associated somehow, your connection is considered anonymous.

When you use Tor, your request to open a page—say, example.com —is not sent directly to that server but first to another Tor node. And just to make things even more complicated, that node then passes the request to another node, which finally connects to example .com. So there’s an entry node, a node in the middle, and an exit node. If I were to look at who was visiting my company site, I would only see the IP address and information from the exit node, the last in the chain, and not the first, your entry node.  
You can configure Tor so it uses exit nodes in a particular country, such as Spain, or even a specific exit node, perhaps in Honolulu.  
**TOR Link**

```
https://www.torproject.org/download/
```

**TOR For Android**

```
https://play.google.com/store/apps/details?id=org.torproject.android&pli=1
```

**TOR For Routers - InvizBox**  
Just plug the InvizBox into your existing router / modem. A new "InvizBox" wifi hotspot will appear. Connect to the new hotspot and follow the one time configuration set up and you're ready to go. All devices that you connect to the InvizBox wifi will route their traffic over the Tor Network.

```
https://www.indiegogo.com/projects/invizbox-privacy-made-easy
```

`TIP 1` Always create any email accounts ,that will be used for anonymous communications, from your TOR connection or after opening whatever VPN you are using.  
`TIP 2` In the homepage of Tor browser you can find links or methods that suggest you volunteer your bandwidth, which makes it easier for other Tor users but comes with risk.  
`TIP 2` Don't use TOR with torrents because it sucks down too much bandwidth. In addition to some exit nodes blocking such traffic by default, it's been proven that an IP address can be found by using torrents over Tor.

###### TorGuard

[Link](https://torguard.net/)  
**Note** If you don't trust the VPN provider you are using then you need to create an anonymous email address and only connect to the VPN from a public Wifi.

#### TOR Bridges

Tor bridges, also called Tor bridge relays, are alternative entry points to the Tor network that are not all listed publicly. Using a bridge makes it harder, but not impossible, for your Internet Service Provider to know that you are using Tor.”

###### TOR Bridges with Tail OS

- Get a list of bridges by vising this page [Tor Project | Bridges](https://bridges.torproject.org/bridges)
- Activate the bridge option in Tails by adding the bridge boot option to the boot menu. The boot menu is the first screen to appear when Tails starts. It is the black screen that says Boot Tails and gives you two options. 1. Live, Live (Fail Safe). When you are on this screen, press Tab and a list of boot options will appear in the form of text at the bottom of the screen. To add a new boot option, add a Space then type “bridge” without the quotes and press enter. You have now activated bridge mode.
- Add the bridges to TOR. Once Tails boots up completely, you will get a warning that you have entered bridge mode and not to delete the default IP address in there, which is 127.0.0.1 This is advice we will follow, so just click OK and the settings window for tor will pop up. At this point you need to add your bridges. So you are going to take the three bridges you got, and enter the IP address and the port.

###### TOR Bridges with Whonix

If you are using Whonix operating system and you want tighter security than the one offered by TOR then you can use TOR bridges.  
To start using TOR bridges simply in Whonix navigate to the config file

```
Start Menu -> Applications -> Settings -> /etc/tor/torrc
OR
/etc/tor/torrc
```

Then add whatever bridge you copied from the Tor bridges page (or a private one if you have it). Then restart Tor for it to take effect. Currently the most  
popular pluggable transports are obfuscated bridges.

#### TOR Pluggable Transports

These attempt to transform your tor traffic into innocent looking traffic that would hopefully be indistinguishable from normal web browsing traffic.

These can be obtained from tor through email. However, you need to request those bridges specifically to get them. You need to use a Gmail or Yahoo account and send an email to [bridges@bridges.torproject.org](mailto:bridges@bridges.torproject.org) and enter in the body of the email `transport obfs2` without the quotes, and for obfs3, simply enter `transport obfs3.

After you receive them, Enter them in this format so that Tails knows which protocol to use.

```
obfs3 83.212.101.2:42782
obfs2 70.182.182.109:54542
```

If you send a request to tor and get a response containing bridges without obfs2 or obsf3 at the beginning of the lines, then these are normal bridges, not obfuscated, and they are likely to be out of obfuscated bridges at the moment. You will have to try again another day. So if you get a response with bridges that are without obfs2  
or 3 at the beginning of each line then be aware these are normal bridges

##### About SSL

Don't trust SSL certificates. These certificates can be obtained anytime from the certificate authority and therefore decrypting your activity.

##### Incognito Mode

In case you lost your access to TOR or it wasn't available for a reason and you needed to do some quick private activity, use the incognito mode in your browser that doesn't record your browsing activity, cookies and doesn't keep your browsing history.

##### Private Search Engines

- DuckDuckGo

##### Blocking Ads and Trackers

There are certain plugins that can be used to block trackers and ads

- NoScript --> Firefox
- ScriptBlock ---> Chrome
- AdBlock ---> All browsers🦊

###### Anonymity Plugins For Chrome and Firefox

If you decide to use Google chrome or FireFox with a VPN, make sure to checkout the below plugins

- [Noscript](https://noscript.net/)
- [ScriptSafe](https://chrome.google.com/webstore/detail/scriptsafe/oiigbmnaadbkfbmpbfijlflahbdbdgdf?hl=en)
- [AdBlock](https://chrome.google.com/webstore/detail/adblock-%E2%80%94-best-ad-blocker/gighmmpiobklfepjocnamgkkbiglidom?hl=en)
- [User-Agent Switcher](https://chrome.google.com/webstore/detail/user-agent-switcher-for-c/djflhoibgkdhkhhcedjiklpkjnoahfmg)  
    You can set yours to look like Internet Explorer. This will fool a lot of malware payloads into thinking you really are browsing with IE and not Firefox or Chrome
- [CanvasBlocker](https://addons.mozilla.org/en-US/firefox/addon/canvasblocker/) 🦊  
    This plugin prevents sites from using Javascript canvas API to fingerprint users. You can block it on every site or be discriminant and block only a few sites. Up to you.

###### Disabling JavaScript Manually in your browser

- Open up a Window and type the following command in the address bar, “about:config” and click the button that says “I’ll be careful, I promise.”
- This will bring up a bunch of settings including a search bar at the top. Enter JavaScript in the search bar and look for the following two entries, `javascript.enabled` and `browser.urlbar.filter.javascript`.
- Right click on these and click `Toggle` and you will see the Value changed to false.
- If you want to enable JavaScript again, just click Toggle again and you will see the value change back to true.

`Again, remember that every time you restart Tails you will have to do this again, so getinto a habit of doing this every time. You never know when your favorite website could become compromised.

### Email Encryption

#### PGP Encryption

#### Definition of PGP and how it works

To encrypt emails, you should use asymmetric encryption. An example would be using PGP.  
For the more technical users, it uses a serial combination of hashing, data compression, symmetric-key cryptography, and finally public-key cryptography. For the less technical users, the process of encrypting messages using PGP is as follows. You create a private key and a public key. The public key is the key you give out to people you want to send you encrypted messages. Your private key, is kept privately by you. This private key is the only key that can unlock messages that were previously locked with your public key.  
`Note: PGP, no matter what “flavor” you use, does not encrypt the metadata— the To and From fields, the subject line, IP Address, and the time-stamp information. Third parties will still be able to see the metadata of your encrypted message; they’ll know that on such-and-such a date you sent an e-mail to someone, that two days later you sent another e-mail to that same person, and so on.

#### PGP in practice

Assuming you have Tails OS running. First thing you are going to want to do is create your own personal key, which consists of your public key that you can give out to people or post in your profiles online.  
As mentioned before, this is the key people use to encrypt messages to send to you. Your personal key also consists of your private key which you can use to decrypt messages that are encrypted using your PGP public key.

##### Creating a PHP key pair

- If you look up to the top right area, you will see a list of icons, and one of them looks like a clipboard.
- You need to click on that clipboard and click **Manage Keys**
- Next click **File -> New**
- Select **PGP Key** and click Continue
- Fill out your anonymous full name
- Optionally fill out an anonymous email and a comment as well.
- Next, click **Advanced Key Options**.
- Make sure Encryption type is set to **RSA** and set key strength to **4096**.
- Once you have done this, click **Create** and it will generate your key.
- Once you have done this, you can view your personal key by clicking the **tab My  
    Personal Keys** .
- You have now created your personal key! To find your PGP public key, you right click on **your personal key** and click **Copy** and it will copy your PGP public key to your clipboard, in which you can paste anywhere you wish.
- Next, you are going to want to save the private key on a secondary USB drive or SD card. If you are running Tails from a USB drive, then you must use a separate drive to store your key on. If you are running Virtual Box, you want to right click on the icon in the bottom right corner that looks like a USB drive, and select your separate drive that you will be using to store your keys on. Again, never store your private keys on your hard drive, keep them OFF your computer.
- To save your private key, you are going to right click on your personal key and click Properties.
- once you have clicked **Properties** , go over to the **tab Details** and click **Export Complete Key**.

`Note`: Remembering that Tails is not installed on your hard drive, so every time you restart Tails you lose all your keys. By saving your keys onto a USB drive or SD card, you can import your keys for use every time you restart it.

##### Importing Other People's Public Key into your Key Ring

The way you import other people’s keys into what’s called your **key ring** is by loading them into a text file.

- You do this with the program called geditText Editor.
- Click Applications -> Accessories -> gedit Text Editor and enter in someone’s public key and hit save.
- Next you can return to your key program from the clipboard icon and click File -> Import and select that file. It will import that person’s public key into your key ring.
- To add future public keys to your key ring, I suggest reopening the same file and just adding the next key below the previous key and each time you open that file it will load all keys within that file. This way you can keep all the PGP public keys together in one file and save it on your SD card or USB drive for future use.

#### Tools for email encryption other than PGP

- **Mailvelope**  
    This tool has plugins for major browsers such as Chrome and Firefox

```
https://mailvelope.com/en
```

Simply type in a passphrase, which will be used to generate the public and private keys. Then whenever you write a Web-based e-mail, select a recipient, and if the recipient has a public key available, you will then have the option to send that person an encrypted message.

- **OpenPGP**

```
https://www.openpgp.org/software/
```

- **GNU Privacy Guard**

```
https://gnupg.org/index.html
```

- **ProtonMail**  
    Its an online mail service that enables both privacy and encryption for your emails.  
    Just sign up for a free account and you are good to go.

```
https://proton.me/
```

- Other ways to achieve security for email messages  
    One way is to simply open an anonymous email address and share it with your recipient with whom you intend to transfer sensitive messages. Then use the draft folder to create messages but not to send them. Your recipient needs to login to the same email and read the drafts folder to read your emails and create new draft emails for you to read. This way no messages are transferred and no worries if someone will read/decrypt these email messages. All you need to do is to change your MAC address-->connect through a virtual machine with TOR or from a public Wifi--> login and write the draft.

**Manually Configuring PGP on Windows**

- Install [Gpg4win - Download Gpg4win](https://www.gpg4win.org/download.html)
- Install [Kleopatra - KDE Applications](https://apps.kde.org/kleopatra/)
- Next, create your key in Kleopatra and choose Export-Certificate-to- Server by right click so you can publish it to a keyserver. Get a trusted friend to "sign" and establish trust.
- Use Claws-Mail client that comes packaged with it or use [Enigmail - Download](https://www.enigmail.net/index.php/en/download) if you're using Thunderbird.
- Send a few messages back and forth to your trusted friend via PGP for the sake of testing

#### Anonymous Email Services

- [PrivateMail](https://privatemail.com/)
- [Tutanota](https://tutanota.com/)
- [FastMail](https://www.fastmail.com/)
- [TorGuard](https://torguard.net/)
- [W3, The Anonymous Remailer](https://gilc.org/speech/anonymous/remailer.html)
- [Guerrilla Mail - Disposable Temporary E-Mail Address](https://www.guerrillamail.com/)

#### Other Technical Precautions

##### Use a Strong Passphrase

First, strong passphrases, not passwords, should be long at least twenty to twenty-five characters. Random characters `ek5iogh#skf&skdwork` best.  
Unfortunately the human mind has trouble remembering random sequences. So use a password manager. Using a password manager is far better than  
choosing your own. I prefer open-source password managers like [Password Safe][https://pwsafe.org/] and [KeePass][https://keepass.info/] that only store data locally on your computer.

##### Never Re-Use Passwords

## Integrity

To verify your files were not altered or backdoored, you will want to use a strong hashing algorithms that can't be reversed or create collisions.  
Strong algorithms: `whirlpool,ripemd160,sha512`  
Example: hashing a password with `whirlpool`

```
whirlpool(pass+salt)
whirlpool(topsecret+@-1012301lkkfslkd3)
```

## Disk Wiping

Remember to perform disk wiping for 3-4 rounds or passes.

#### Linux

##### DD

- Using dd: You could write random data to the disk you want to destroy but its slow process.

```
if=/dev/urandom of=/dev/sda
```

#### Windows

- [File Shredder](https://www.fileshredder.org/)
- [CCleaner](https://www.ccleaner.com/ccleaner)
- [Data Removal: Darik's Boot and Nuke - DBAN](https://dban.org/)

## Anonymous Payments

To achieve anonymity while paying online you need to do the following:

- Find an e-mail provider that allows you to sign up without SMS validation. Or you can sign up for a Skype-in number using Tor and a prepaid gift card. With Skype-in, you can receive voice calls to verify your identity. Make sure you are out of camera view (i.e., not in a Starbucks or anywhere else with camera surveillance). Use Tor to mask your location when you sign up for this e-mail service.
- Using your new anonymous e-mail address, sign up at a site such as paxful.com, again using Tor, to sign up for a Bitcoin wallet and buy a supply of Bitcoin. Pay for them using the prepaid gift cards.
- Set up a second anonymous e-mail address and new secondary Bitcoin wallet after closing and establishing a new Tor circuit to prevent any association with the first e-mail account and wallet.
- Use a Bitcoin laundering service such as [bitlaunder.com](https://publish.obsidian.md/cybersecuritynotes/bitlaunder.com) or [Bitcoin Fog](http://bitcoinfog.info/)to make it hard to trace the currency’s origin. Have the laundered Bitcoin sent to the second Bitcoin address.23
- Sign up for a VPN service using the laundered Bitcoin that does not log traffic or IP connections. You can usually find out what is logged by reviewing the VPN provider ’s privacy policy.
- Connect to the internet using an open Wifi but stay out of public cameras or you can create a hot-spot powered from a burner phone purchased using gift cards.

**Note** Bitcoin by itself is not anonymous. They can be traced through what’s called a blockchain back to the source of the purchase; similarly, all subsequent purchases can be traced as well. So Bitcoin by itself is not going to hide your identity. We will have to run the funds through an anonymity mechanism: converting prepaid gift cards into Bitcoin, then running the Bitcoin through a laundering service. This process will result in anonymized Bitcoin to be used for future payments. You will need the laundered Bitcoin, for example, to pay for our VPN service and any future purchase.  
Using Tor, you can set up an initial Bitcoin wallet at [paxful](https://publish.obsidian.md/cybersecuritynotes/paxful.com) or other Bitcoin wallet sites.

`So how do you launder Bitcoin before using it`  
There are services called tumblers that will take Bitcoin from a variety of sources and mix—or tumble them together so that the resulting Bitcoin retains its value but carries traces of many owners. This makes it hard for someone to say later which owner made a certain purchase. But you have to be extremely careful, because there are tons of scams out there.

Additionally, When you withdraw your coins from (a mixer or launderer) BitcoinFog, please make sure you send them to a new wallet, and not the same wallet that you used to deposit them into BitcoinFog. Another option you can have when withdrawing the coins from BitcoinFog, is to get BitcoinFog to withdraw the coins directly to the person you want to buy something from. This takes the step of creating a new wallet and then having to forward it on and will keep things again extremely hard to track. Just keep their transaction fees in mind to make sure your desired seller is going to receive the correct amount of Bitcoins needed for the purchase or exchange.

## Anonymity For Blackhat Hackers

The below notes apply to Blackhat hackers who want to shady stuff.

`EVERY THING WE MENTIONED ABOVE FOR NON-BLACKHAT HACKERS APPLY TO BLACKHAT HAKCERS HERE`

### Things to Do Before Starting To Hack

- Don't use your Home WIFI or your cellphone hotspot for internet access. Use an internet access that doesn't eventually lead to you. Example is Starbucks Internet.
- Use a dedicated OS for hacking preferably booted from Live MicroSD card or any sort of portable storage if possible. If not use an OS on a virtual machine that is installed on a completely different laptop. Don't use your own laptop for this stuff. Gentoo Linux is a good lightweight OS for that purpose. Format with EXT2 to avoid journals.
- Use a MAC address changer.

### After You Start Hacking

- When conducting web application attacks, make sure to spoof/change your user agent because system admins can correlate data in their access logs and they can map your user agent.

### You Finished Hacking

#### Clearing Tracks

## FAQs

### Does My Home IP Address reveal my location?

No, If you purchased a static IP address it will be associated with your subscriber account and home address, otherwise your external IP address will  
be generated from a pool of addresses assigned to your Internet service provider.  
Therefore your public IP address is associated with the internet service provider in your country/city/state.

### Can Others Trace and Identify me based on Public IP Address?

In theory, your identity (name, surname ,home address) is registered with the internet service provider you have subscribed to when you purchased your internet membership only so unless someone hacks to your cell phone/PC no one can map your IP to your identity. Only The government HAS A CHANCE to do that. Here is how;

If there was a court order filed by someone against you claiming that you were trying to hack or you have hacked one of their digital assets (accounts, PCs, etc) and if there were records of the public IP/IPs in the logs (account access logs, web server logs), then the police along with the communication company will map the existing IP addresses showing in the logs with the timestamp and current existing subscriber information who was using these IPs at the said timestamp.

If they found a common name using this/those IP/IPs then they can reveal your identity.

### Is VOIP better than mobile phones and landlines for privacy and encryption?

The good news is that VoIP phone systems do use encryption; specifically, something called session description protocol security descriptions, or SDES.  
The bad news is that on its own, SDES is not very secure in that the encryption key is not shared over  
SSL/TLS.  
So the answers is with proper end to end encryption, VOIP can be better secure alternative to regular mobile and landlines for secure calls.

### What are some secure VOIP apps?

Signal is a free, open-source VoIP system for mobile phones that provides true end-to-end encryption for both iPhone and Android. The key management is handled only between the calling parties, not through any third party. The only copies of the encryption keys are stored on the users’ devices and once the call ends, those session keys are destroyed which renders the process of trying to decrypt the call useless.

In addition to using end-to-end encryption, Signal also uses `perfect forward secrecy` (PFS). It’s a system that uses a slightly different encryption key for every call, so that even if someone does manage to get hold  
of your encrypted phone call and the key that was used to encrypt it, your other calls will remain secure.

All PFS keys are based on a single original key, but the important thing is that if someone compromises one key, it doesn’t mean your potential adversary has access to your further communications.

### What are secure text messaging alternatives to SMS ?

- Telegram: Telegram is another messaging app that offers encryption Researchers have, however, found an adversary can compromise Telegram servers and get access to critical data.18 And researchers have found it easy to retrieve encrypted Telegram messages, even after they have been deleted from the device. So Telegram is secure but there is a risk that your encrypted messages get stolen from Telegram servers so its usable app but there is a risk.
- [ChatSecure](https://guardianproject.info/)
- Signal
- Cryptocat
- Tor Messenger
- [TorChat](https://github.com/prof7bit/TorChat/wiki)
- [ChatCrypt](https://www.chatcrypt.com/)

And in general, when you’re on the app store or Google Play, look for apps that use something called `off-the-record messaging`, or `OTR`. It is a higher-standard end-to-end encryption protocol used for text messages, and it can be found in a number of products. In addition to using `PFS`

### What If someone such as the customs ask for your password/key to examine your equipment?

When traveling, some customs in some countries do extensive examination of digital equipment so its best practice to encrypt your files, upload them to the cloud, wipe them from your device then when you are inside the country you can download them back.

Another method is to clone your entire system that contains encrypted/sensitive data and ship it over to the destination you are going to. Its best if someone you trust handles the delivery. After you do that, you WIPE the sensitive data from your system if you are too worried your devices might be searched/examined.

### How would government monitor the Dark web?

They plant and control what are called exit nodes in TOR browser, the points at which an Internet request is passed to one of these hidden services, though that still wouldn’t allow identification of the initial requester.  
To do that the government observer would have to see that a request was made to access site X and that a few seconds earlier, someone in New Hampshire fired up the Tor browser. The observer might suspect that the two events were related. Over time, access to the site and repeated access to Tor around the same time could establish a pattern. One way to avoid creating that pattern is to keep your Tor browser connected at all times.

### Can others eavesdrop on what I type on my Keyboard other than using Keyloggers?

Yes, Using a strong antenna, sitting in a van outside your home, Others could be picking up on your keystrokes on a wired and wireless keyboard. Wired and wireless keyboards emit electromagnetic waves, because they contain electronic components. This electromagnetic radiation could reveal sensitive information such as keystrokes.  
There are certain products you can buy to disrupt and obstruct the transmission of these electromagnetic signals. Check [[Smart Meter Shields | Product categories | Less EMF](https://lessemf.com/product-category/emf-shielding/smart-meter-shields/)

### What is a Cold Boot Attack? and does it really break whole disk encryption?

Cold boot attacks rely on extracting information from the RAM. Shutting down a computer through its normal shutdown cycle usually goes through a process of clearing the RAM. However, if the computer loses power abruptly like in a power outage, the computer does not go through its normal shut down cycle and some information remains on the RAM chips for a few seconds up to a few minutes.

So by shutting down the computer abruptly and by using an analysis tool others can access the contents of the RAM or DRAM and search for key files (such as PGP keys) held in the RAM that could be used to decrypt encrypted volumes (drives) on your computer. They successfully were able to decrypt volumes using BitLocker, FileVault, dm crypt, and TrueCrypt.

A few key points to extract from here are that properly shutting down your computer reduces, if not completely eliminates this risk. Additionally using DDR3 and DDR4 RAM is a safer option than DDR1 and DDR2 RAM. DDR3 is known to hold  
memory for a much shorter time than DDR2.

## Other Online Tools

- Delete all your tweets

```
https://twitwipe.com/
https://tweetdelete.net/
```

- VPNs

```
https://help.riseup.net/en/vpn
```