#!/usr/bin/env python3
import os
import re
from datetime import datetime

# Copy images
os.system('mkdir -p assets/img/htb-writeups && cp -r htb_image/* assets/img/htb-writeups/ 2>/dev/null')

def sanitize_filename(filename):
    """Convert filename to Jekyll post format"""
    # Remove directory and extension
    base = os.path.splitext(filename)[0]
    # Replace special chars
    base = base.replace(' ', '-').replace('~', '').lower()
    base = re.sub(r'[^a-z0-9-]', '', base)
    return base

def extract_title(filename):
    """Extract title from filename"""
    base = os.path.splitext(filename)[0]
    # Remove directory prefix if present
    base = os.path.basename(base)
    return base

def update_image_paths(content):
    """Update image paths to use /assets/img/htb-writeups/"""
    # Replace ![[Pasted image...]] with proper markdown image syntax
    pattern = r'!\[\[Pasted image ([^\]]+)\]\]'
    def replacer(match):
        img_name = match.group(1)
        return f'![{img_name}](/assets/img/htb-writeups/Pasted image {img_name})'
    content = re.sub(pattern, replacer, content)
    return content

def create_post(filename, directory, index):
    """Create a Jekyll blog post from a writeup file"""
    filepath = os.path.join(directory, filename)
    
    # Read content
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Extract title
    title = extract_title(filename)
    
    # Update image paths
    content = update_image_paths(content)
    
    # Generate date (spread posts over recent dates)
    days_ago = len(all_files) - index - 1
    post_date = datetime.now().replace(day=1)  # Start of current month
    
    # Create front matter
    front_matter = f"""---
title: {title}
date: {post_date.strftime('%Y-%m-%d')} 00:00:00 +0000
categories: [HackTheBox Writeups]
tags: [hackthebox, {directory.lower()}]
---
"""
    
    # Create output filename
    sanitized = sanitize_filename(filename)
    output_file = f"_posts/{post_date.strftime('%Y-%m-%d')}-{sanitized}.md"
    
    # Write post
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(front_matter + content)
    
    return output_file

# Get all files
linux_files = [(f, 'Linux') for f in os.listdir('Linux') if f.endswith('.md') and f != 'Untitled']
windows_files = [(f, 'Windows') for f in os.listdir('Windows') if f.endswith('.md')]
all_files = linux_files + windows_files

print(f"Processing {len(all_files)} writeup files...")

# Process each file
for i, (filename, directory) in enumerate(all_files):
    try:
        output = create_post(filename, directory, i)
        print(f"Created: {output}")
    except Exception as e:
        print(f"Error processing {filename}: {e}")

print("Done!")

