import streamlit as st
import re
import pickle
import logging
import os

# Set up the base directory for model files
BASE_MODEL_PATH = os.path.join(os.getcwd(), "models")  # You can change this path if necessary

# Check if model files exist
def check_model_path(file_name):
    file_path = os.path.join(BASE_MODEL_PATH, file_name)
    if not os.path.exists(file_path):
        logging.error(f"Model file {file_name} not found at {file_path}")
        return None
    return file_path

# Logging setup
logging.basicConfig(level=logging.INFO)

def load_model(file_name):
    file_path = check_model_path(file_name)
    if file_path is None:
        return None
    try:
        with open(file_path, 'rb') as file:
            return pickle.load(file)
    except Exception as e:
        logging.error(f"Error loading model {file_name}: {e}")
        return None

# Load ML models
spam_tfidf_vectorizer = load_model("feature_extraction_spam.pkl")
spam_classifier = load_model("svm_spam.pkl")
phishing_tfidf_vectorizer = load_model("tfidf_vectorize_phishing.pkl")
phishing_classifier = load_model("lr_classifier_phishing.pkl")

class SpamDetector:
    def __init__(self):
                self.spam_keywords = [
                    "sms", "reply", "end", "sptv", "txt", "stop", "cancel", 
                    "unsubscribe", "limited time", "offer", "urgent", 
                    "Urgent", "Immediate action required", "Act now", "Failure to act", 
                    "Limited-time offer", "Hurry", "Expiring soon", "Urgent alert", 
                    "Risk-free", "Immediate refund", "Unclaimed funds", "Last chance", 
                    "Final notice", "Your account is locked", "Verify now", 
                    "Prevent suspension", "Unauthorized activity", 
                
                    # Money & Financial Scams
                    "Winner", "You have won", "Cash prize", "Lottery", "$1000", 
                    "Free money", "Get rich quick", "Double your money", 
                    "Investment opportunity", "Cryptocurrency", "High returns", 
                    "No credit check", "Tax refund", "Pre-approved loan", "Make money fast", 
                
                    # Fake Tech & Security Alerts
                    "Your account has been compromised", "Unusual login attempt", 
                    "Security warning", "Virus detected", "Your computer is infected", 
                    "Contact support immediately", "Call now", "Microsoft Security Team", 
                    "PayPal alert", "Banking issue", "Suspicious","Suspicious activity", "Payment failure", 
                
                    # Job & Work-from-Home Scams
                    "Work from home", "Earn $5000 per month", "No experience needed", 
                    "Guaranteed income", "Flexible working hours", "Remote job", 
                    "Passive income", "Exclusive job offer", "Data entry job", "Recruitment team", 
                
                    # Fake Promotions & Giveaways
                    "Free gift", "Claim your prize", "Special offer", "You have been selected", 
                    "Buy one get one free", "Free trial", "Complimentary", "No hidden fees", 
                    "Exclusive deal", "VIP access", 
                
                    # Fake Subscription & Payment Scams
                    "Your subscription is expiring", "Update your payment details", 
                    "Payment failure", "Your service has been suspended", "Renew now", 
                    "Credit card required", "Billing issue", 
                
                    # Loan & Financial Assistance Scams
                    "Pre-approved loan", "No collateral required", "0% interest", 
                    "Personal loan offer", "Instant approval", "Government grant", 
                
                    # Common Phishing Words & Phrases
                    "Click here", "Verify your identity", "Login required", "Confirm your account", 
                    "Secure your information", "Your account will be locked", "Reset your password"
                ]

                self.spam_threshold = 2  
    
    def ml_spam_detection(self, text):
        if spam_tfidf_vectorizer and spam_classifier:
            try:
                vectorized_text = spam_tfidf_vectorizer.transform([text])
                prediction = spam_classifier.predict(vectorized_text)[0]
                logging.info(f"ML Model Prediction: {prediction}")
                return prediction == 1
            except Exception as e:
                logging.error(f"ML Spam detection error: {e}")
        return False
    
    def contains_spam_keywords(self, text):
        return sum(keyword.lower() in text.lower() for keyword in self.spam_keywords)
    
    def detect(self, text):
        if not isinstance(text, str) or len(text.strip()) < 60:
            return "Insufficient Text"
        
        spam_score = self.contains_spam_keywords(text)
        ml_result = self.ml_spam_detection(text)
        
        logging.info(f"Spam Score: {spam_score}, ML Result: {ml_result}")
        
        if spam_score >= self.spam_threshold or ml_result:
            return "Spam"
        return "Not Spam"

class PhishingDetector:
    def detect(self, text):
        if not isinstance(text, str) or len(text.strip()) < 60:
            return "Insufficient Text"
        
        if re.search(r'https?://\S+', text):
            return "Phishing"
        
        try:
            vectorized_text = phishing_tfidf_vectorizer.transform([text])
            prediction = phishing_classifier.predict(vectorized_text)[0]
            logging.info(f"Phishing Model Prediction: {prediction}")
            return "Phishing" if prediction == 1 else "Not Phishing"
        except Exception as e:
            logging.error(f"Phishing detection error: {e}")
            return "Error"

def main():
    st.set_page_config(page_title="Message Security Classifier", layout="wide")
    st.title("🛡️ Message Security Classifier")
    
    page = st.sidebar.radio("Select Detection Type", ["Spam Detection", "Phishing Detection"])
    message_input = st.text_area("Enter message content (minimum 60 characters)", height=200)
    
    char_count = len(message_input.strip())
    st.write(f"Character count: {char_count}/60")
    
    if page == "Spam Detection":
        st.header("Spam Detection")
        if st.button("Check for Spam"):
            if char_count < 60:
                st.warning("⚠️ Please enter at least 60 characters")
            else:
                detector = SpamDetector()
                result = detector.detect(message_input)
                
                if result == "Spam":
                    st.warning("🚩 SPAM DETECTED")
                else:
                    st.success("✅ Not spam")
    
    elif page == "Phishing Detection":
        st.header("Phishing Detection")
        if st.button("Check for Phishing"):
            if char_count < 60:
                st.warning("⚠️ Please enter at least 60 characters")
            else:
                detector = PhishingDetector()
                result = detector.detect(message_input)
                
                if result == "Phishing":
                    st.warning("🚨 PHISHING DETECTED")
                else:
                    st.success("✅ Not phishing")

if __name__ == "__main__":
    main()
