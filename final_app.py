import streamlit as st
import re
import pickle

# Loading the vectorizers and classifiers
with open("feature_extraction_spam.pkl", 'rb') as file: 
    spam_tfidf_vectorizer = pickle.load(file)

with open("svm_spam.pkl", 'rb') as file:
    spam_classifier = pickle.load(file)

with open("tfidf_vectorize_phishing.pkl", 'rb') as file: 
    phishing_tfidf_vectorizer = pickle.load(file)

with open("lr_classifier_phishing.pkl", 'rb') as file:
    phishing_classifier = pickle.load(file)

# Suspicious TLDs often associated with phishing domains
SUSPICIOUS_TLDS = ['.xyz', '.club', '.top', '.work', '.info', '.biz', '.tk', '.ml', '.ga', '.cf']

# Suspicious keywords often found in phishing URLs
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "password", "bank", "paypal", 
    "signin", "billing", "support", "service", "confirm", "identity", "credit", "lottery", "winner"
]

# Function to extract URLs
def extract_url(text):
    url_pattern = re.compile(r'http[s]?://\S+|www\.\S+')
    return re.findall(url_pattern, text)

# Function to check if a URL uses a suspicious TLD
def is_suspicious_tld(url):
    return any(url.lower().endswith(tld) for tld in SUSPICIOUS_TLDS)

# Function to check if a URL contains suspicious keywords
def contains_suspicious_keywords(url):
    return any(keyword in url.lower() for keyword in SUSPICIOUS_KEYWORDS)

# Function to check for multiple subdomains (common in phishing URLs)
def has_multiple_subdomains(url):
    try:
        domain = re.findall(r'http[s]?://([^/]+)', url)[0]  # Extract domain from URL
        return domain.count('.') > 2  # More than two dots in domain
    except IndexError:
        return False

# Function to check for IP-based URLs (commonly used in phishing)
def is_ip_url(url):
    ip_pattern = re.compile(r'http[s]?://(?:\d{1,3}\.){3}\d{1,3}(?:\:\d+)?(?:/\S*)?')
    return bool(re.match(ip_pattern, url))

# Function to detect phishing URLs based on multiple heuristics
def detect_phishing_url(url):
    return is_suspicious_tld(url) or contains_suspicious_keywords(url) or has_multiple_subdomains(url) or is_ip_url(url)

# Function to detect phishing words in text
def contains_suspicious_words(text):
    phishing_words = [
        "click here", "credit", "prize", "urgent", "account", "verify", "free", 
        "limited time", "login", "password", "update", "security", "confirm", 
        "offer", "lottery", "important", "immediately", "risk", "billing",
        "action required", "claim", "unsubscribe", "suspended", "identity", "winner"
    ]
    return any(f" {word} " in f" {text.lower()} " for word in phishing_words)

# Title and subtitle
st.title("Email Spam and Phishing Classification App")
st.subheader("Built with Streamlit & Python")

# Text input field
user_input = st.text_area("Enter the email text", placeholder="Type your email content here...")

# Button and prediction logic
if st.button("Predict"):
    if user_input.strip() == "":
        st.info("Please enter text to predict.")
    else:
        # Normalize text input
        normalized_input = user_input.strip().lower()
        
        # Transform the user input for Spam Detection
        spam_features = spam_tfidf_vectorizer.transform([normalized_input])
        spam_prediction = spam_classifier.predict(spam_features)[0]
        spam_confidence = spam_classifier.decision_function(spam_features)[0]  # Confidence score
        
        # Transform the user input for Phishing Detection
        phishing_features = phishing_tfidf_vectorizer.transform([normalized_input])
        phishing_prediction = phishing_classifier.predict(phishing_features)[0]
        phishing_confidence = phishing_classifier.decision_function(phishing_features)[0]  # Confidence score
        
        # Check for URLs in the input text
        urls = extract_url(normalized_input)
        phishing_urls = [url for url in urls if detect_phishing_url(url)]

        # Determine final categories
        is_spam = spam_prediction == 1 and spam_confidence > 0.5  # Adjust confidence threshold
        is_phishing = phishing_prediction == 1 or contains_suspicious_words(normalized_input) or phishing_urls

        # Display results
        if is_phishing:
            st.error("This email contains phishing content.")
            if phishing_urls:
                st.warning(f"Suspicious URLs detected: {phishing_urls}")
        elif is_spam:
            st.error("This email is classified as spam.")
        else:
            st.success("This email does not contain spam or phishing content.")
