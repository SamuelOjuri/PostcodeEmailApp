import streamlit as st
import os
import re
import extract_msg
import fitz
import pytesseract
import pandas as pd
import io
from PIL import Image, UnidentifiedImageError
import email
from email import policy
from email.parser import BytesParser

# Regular expressions for postcode extraction
UK_POSTCODE_PATTERN = r'\b[A-Z]{1,2}[0-9R][0-9A-Z]? ?[0-9][A-Z]{2}\b'
POSTCODE_FOLLOW_PATTERN = r'(?i)\bpostcode[:\s]+(\S+)'
SIGNATURE_PATTERNS = [
    r'(?i)\bBest[, ]?\b', r'(?i)\bKind[, ]?\b', r'(?i)\bRegards[, ]?\b',
    r'(?i)\bThanks[, ]?\b', r'(?i)\bThank[, ]?\b', r'(?i)\bBest regards[, ]?\b',
    r'(?i)\bSincerely[, ]?\b', r'(?i)\bYours faithfully[, ]?\b', r'(?i)\bMany[, ]?\b',
    r'(?i)\bMany thanks[, ]?\b'
]

# Add the missing patterns for additional stopping points
LINK_PATTERN = r'https?://\S+'
EMAIL_PATTERN = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
IMAGE_PATTERN = r'\b(?:https?:\/\/)?(?:[a-zA-Z0-9_-]+\.)+[a-zA-Z]{2,6}\/[a-zA-Z0-9_\-]+\.(jpeg|png|gif)\b'
TAPEREDPLUS_PATTERN = r'\bTaperedPlus\b'

# Extraction functions
def extract_postcode(text):
    match = re.search(UK_POSTCODE_PATTERN, text)
    return match.group(0) if match else None

def extract_postcode_following(text):
    match = re.search(POSTCODE_FOLLOW_PATTERN, text)
    return match.group(1) if match else None

def extract_from_body_top_lines(body, lines=3):
    for line in body.split('\n')[:lines]:
        postcode = extract_postcode(line) or extract_postcode_following(line)
        if postcode:
            return postcode
    return None

def extract_postcode_before_stopping_points(body):
    stopping_points = []
    
    # Check for signature patterns
    for pattern in SIGNATURE_PATTERNS:
        match = re.search(pattern, body)
        if match:
            stopping_points.append(match.start())
    
    # Also check for links, emails, images, and specific text
    for pattern in [LINK_PATTERN, EMAIL_PATTERN, IMAGE_PATTERN, TAPEREDPLUS_PATTERN]:
        match = re.search(pattern, body)
        if match:
            stopping_points.append(match.start())
    
    # Find earliest stopping point and extract postcode before it
    if stopping_points:
        body = body[:min(stopping_points)]
    
    return extract_postcode(body) or extract_postcode_following(body)

def extract_text_from_pdf(file_path):
    text = ""
    pdf_document = fitz.open(file_path)

    for page_num in range(pdf_document.page_count):
        page = pdf_document[page_num]
        text += page.get_text()

        images = page.get_images(full=True)
        for img in images:
            base_image = pdf_document.extract_image(img[0])
            image_bytes, image_ext = base_image["image"], base_image["ext"]

            if image_ext.lower() in ["png", "jpeg", "jpg"]:
                try:
                    image = Image.open(io.BytesIO(image_bytes))
                    text += pytesseract.image_to_string(image)
                except UnidentifiedImageError:
                    continue

    return text.lower()

def process_emails(folder_path):
    email_data = []

    for root, dirs, files in os.walk(folder_path):
        for filename in files:
            file_path = os.path.join(root, filename)

            if filename.lower().endswith(".msg"):
                msg = extract_msg.Message(file_path)
                subject, sender, body = msg.subject, msg.sender, msg.body or ""

                postcode = (
                    extract_postcode(subject) or
                    extract_from_body_top_lines(body) or
                    extract_postcode_following(subject) or
                    extract_postcode_following(body) or
                    extract_postcode_before_stopping_points(body)
                )

                email_data.append({
                    'Filename': filename,
                    'Sender': sender,
                    'Subject': subject,
                    'Extracted_Postcode': postcode
                })

            elif filename.lower().endswith(".pdf"):
                pdf_text = extract_text_from_pdf(file_path)
                postcode = extract_postcode(pdf_text) or extract_postcode_following(pdf_text)
                email_data.append({
                    'Filename': filename,
                    'Sender': "",
                    'Subject': "",
                    'Extracted_Postcode': postcode
                })

    return pd.DataFrame(email_data)

# Streamlit UI
st.title("📧 Postcode Extractor App")

uploaded_files = st.file_uploader("Drag and drop email (.msg, .eml) or PDF files here", 
                                 type=["msg", "pdf", "eml"],
                                 accept_multiple_files=True)

extract_button = st.button("Extract Postcodes")

if extract_button:
    if uploaded_files:
        with st.spinner("Extracting postcodes..."):
            email_data = []
            
            for uploaded_file in uploaded_files:
                if uploaded_file.name.lower().endswith(".msg"):
                    # Save the uploaded file temporarily to process with extract_msg
                    temp_file_path = f"temp_{uploaded_file.name}"
                    with open(temp_file_path, "wb") as f:
                        f.write(uploaded_file.getvalue())
                    
                    try:
                        msg = extract_msg.Message(temp_file_path)
                        subject, sender, body = msg.subject, msg.sender, msg.body or ""
                        
                        # Close the message object to release the file handle
                        msg.close()
                        
                        postcode = (
                            extract_postcode(subject) or
                            extract_from_body_top_lines(body) or
                            extract_postcode_following(subject) or
                            extract_postcode_following(body) or
                            extract_postcode_before_stopping_points(body)
                        )

                        email_data.append({
                            'Filename': uploaded_file.name,
                            'Sender': sender,
                            'Subject': subject,
                            'Extracted_Postcode': postcode
                        })
                    finally:
                        # Clean up the temporary file
                        if os.path.exists(temp_file_path):
                            os.remove(temp_file_path)
                        
                elif uploaded_file.name.lower().endswith(".eml"):
                    # Process .eml file
                    try:
                        # Parse the .eml file
                        eml_bytes = uploaded_file.getvalue()
                        
                        # Save the .eml content to a temporary file
                        temp_file_path = f"temp_{uploaded_file.name}"
                        with open(temp_file_path, "wb") as f:
                            f.write(eml_bytes)
                        
                        try:
                            # Parse using file instead of bytes
                            with open(temp_file_path, "rb") as f:
                                msg = email.message_from_binary_file(f, policy=policy.default)
                            
                            # Extract header information
                            subject = str(msg.get('subject', ''))
                            sender = str(msg.get('from', ''))
                            
                            # Extract body
                            body = ""
                            
                            # Try to get plain text content
                            for part in msg.walk():
                                content_type = part.get_content_type()
                                if content_type == "text/plain":
                                    try:
                                        body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
                                    except:
                                        continue
                            
                            # If no text content, try HTML
                            if not body:
                                for part in msg.walk():
                                    content_type = part.get_content_type()
                                    if content_type == "text/html":
                                        try:
                                            html_body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                                            # Simple HTML strip
                                            body += re.sub('<[^<]+?>', '', html_body)
                                        except:
                                            continue
                            
                            postcode = (
                                extract_postcode(subject) or
                                extract_from_body_top_lines(body) or
                                extract_postcode_following(subject) or
                                extract_postcode_following(body) or
                                extract_postcode_before_stopping_points(body)
                            )
                            
                            email_data.append({
                                'Filename': uploaded_file.name,
                                'Sender': sender,
                                'Subject': subject,
                                'Extracted_Postcode': postcode
                            })
                        finally:
                            # Clean up the temporary file
                            if os.path.exists(temp_file_path):
                                os.remove(temp_file_path)
                            
                    except Exception as e:
                        st.error(f"Error processing .eml file {uploaded_file.name}: {str(e)}")
                
                elif uploaded_file.name.lower().endswith(".pdf"):
                    # Save the uploaded file temporarily
                    temp_file_path = f"temp_{uploaded_file.name}"
                    with open(temp_file_path, "wb") as f:
                        f.write(uploaded_file.getvalue())
                    
                    try:
                        pdf_text = extract_text_from_pdf(temp_file_path)
                        postcode = extract_postcode(pdf_text) or extract_postcode_following(pdf_text)
                        email_data.append({
                            'Filename': uploaded_file.name,
                            'Sender': "",
                            'Subject': "",
                            'Extracted_Postcode': postcode
                        })
                    finally:
                        # Clean up the temporary file
                        if os.path.exists(temp_file_path):
                            os.remove(temp_file_path)
            
            df = pd.DataFrame(email_data)
            st.success("Extraction complete!")
            st.dataframe(df)

            # Create Excel file in memory
            buffer = io.BytesIO()
            with pd.ExcelWriter(buffer, engine='xlsxwriter') as writer:
                df.to_excel(writer, index=False)
            
            buffer.seek(0)
            
            st.download_button(
                label="Download Extracted Data as Excel",
                data=buffer,
                file_name="Extracted_Postcodes.xlsx",
                mime="application/vnd.ms-excel"
            )
    else:
        st.error("Please upload at least one file first.")

