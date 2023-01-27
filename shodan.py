import requests
import time
from utils.conf import *
from utils.utils import Shodan, filter_exists

if __name__ == '__main__':
    shodan = Shodan()
    shodan.run()

    