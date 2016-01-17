# Project 3 : Item Catalog

This project 3 present a prototype Item Catalog system for restaurant management. 
Collaborate with Flask via Python and SQLite Database to implement CRUD method on RESTful API style.
Support third party authentication form Google+ and Facebook account, 
and extra feature by export restaurant/menu data to JSON and XML style.

## Quick Start

1. Install [Git 2.6.3](http://git-scm.com/downloads)
2. Install [Virtual Box 4.3.28](https://www.virtualbox.org/wiki/Download_Old_Builds_4_3)
3. Install [Vagrant 1.7.4](https://www.vagrantup.com/downloads.html)
4. Clone project by 
    * "git clone https://github.com/wats0n/udacity_p3_item_catalog.git"
5. Check if "Vagrantfile" in download project directory.
6. Using "Git bash here" on mouse menu
7. Execute following command to setup and login VM:
    * vagrant up
    * vagrant ssh
8. In VM prompt, typing following command to project directory:
    * cd /vagrant/
9. Using below command to setup SQLite DataBase
    * python database_setup.py
10. Executing "python project.py" to test Item Catalog.
11. In Host Browser like Chrome or Mozilla, input url: "http://localhost:5000" to connect Web Server.
12. Login with upper-right "Hi, Guest (Login)", then selet by Google+ or Facebook.
13. Look around by Add/Edit/Delete Restaurant/Menu on website!
14. If you want logout, press upper-left "Hi, <Your Name> (Logout)".
15. Quit python web server, press Ctrl+C (^C) to stop web service. 
16. Exit vagrant by "exit" command, exit git-bash environment is "exit" command, too.

##Extra Feature

A. JSON Endpoints
    * ALL Restaurants: http://localhost:5000/restaurant/JSON
    * ALL Menus in Restaurant: http://localhost:5000/restaurant/<restaurant_id>/menu/JSON
    * Specific Menu in Restaurant: http://localhost:5000/restaurant/<restaurant_id>/menu/<menuitem_id>/JSON
B. XML Endpoints
    * ALL Restaurants: http://localhost:5000/restaurant/XML
    * ALL Menus in Restaurant: http://localhost:5000/restaurant/<restaurant_id>/menu/XML
    * Specific Menu in Restaurant: http://localhost:5000/restaurant/<restaurant_id>/menu/<menuitem_id>/XML
    
## Creator(s)
------
Watson Huang (wats0n)
11/08, 2015