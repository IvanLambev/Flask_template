import random
import nlpcloud
import bs4
import requests


def get_text(url):
    # Make request to the website

    if not is_valid_url(url):
        return "Invalid URL"

    response = requests.get(url, proxies=get_working_proxy())

    # Parse HTML content with BeautifulSoup
    soup = bs4.BeautifulSoup(response.content, 'html.parser')

    # Extract all text from the website
    text = soup.get_text()

    return text


# validation
def is_valid_url(url):
    try:
        response = requests.head(url)
        return response.status_code == 200
    except:
        return False



