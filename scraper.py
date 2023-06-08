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


# proxy config
def get_proxies():
    with open('proxylist.txt', 'r') as f:
        proxies = f.readlines()

    return proxies


def get_random_proxy():
    return {'https': random.choice(get_proxies())}


proxies = get_proxies()


def get_working_proxy():
    for i in range(1, 10):
        proxy = get_random_proxy()
        print("Trying proxy...")
        try:
            r = requests.get("https://www.google.com", proxies=proxy, timeout=2)
            if r.status_code == 200:
                print("Proxy is working")
                return proxy
        except:
            print("Proxy is not working")
            pass
    return None


# summary
def summarize_text(text_to_summarize):
    client = nlpcloud.Client("bart-large-cnn", "f771bc4e9647a3607f917eae5b5f609f7b320219", gpu=False, lang="en")
    response = client.summarization(text_to_summarize, size="large")
    summary_text = response['summary_text']
    return summary_text
