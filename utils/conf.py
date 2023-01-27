# Prepare your search here
'''
set cookie and user_agent with already log-on account
you can gather this information from shodan.io GET request found in network tab in inspect window(CTRL+SHIFT+C)
'''
cookie = 'polito="22b970417d7260ac5d517818abfd73bf43d2f051634ed91f350dcff8cabaa65b!"'
user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/200.0"

'''
set ip or ip range(use slash subnet mask notation) of network you are willing to scan or leave it empty (ip_range = "")
'''
ip_range = ""

'''
interval time(in seconds) between requests to prevent flooding, set 0 if you do not care
'''
interval = 2

'''
you can add some more filters in dict format, for example {'city': 'London'}
one of the usage examples is when you wanna search by city or country not by ip address(then you can consider leaving ip_range property empty)
'''
additional_filters = {'city': 'London'}

'''
Note, that you can add your additional queries in queries.txt
if you set everything up simply run it: python shodan.py
Your output will be displayed on console and saved to the results.txt file
'''