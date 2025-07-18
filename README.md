# KonH4cks Blog

A cybersecurity blog built with Jekyll, based on the capt-meelo template.

## Features

- Clean, responsive design
- Category-based navigation
- Syntax highlighting for code
- Social media integration
- SEO optimized
- Mobile-friendly

## Local Development

### Prerequisites

- Ruby 3.3+
- Bundler

### Installation

1. Clone the repository:
```bash
git clone https://github.com/konh4cks/konh4cks.github.io.git
cd konh4cks.github.io
```

2. Install dependencies:
```bash
bundle install
```

3. Run the development server:
```bash
bundle exec jekyll serve --host 0.0.0.0 --port 4000
```

4. Open your browser and navigate to `http://localhost:4000`

## Adding New Posts

Create new posts in the `_posts` directory with the following naming convention:
```
YYYY-MM-DD-title.md
```

Example:
```markdown
---
layout: post
title: "My New Blog Post"
date: 2024-07-18
categories: [pentest]
tags: [web, xss, writeup]
---

Your content here...
```

## Categories

The blog supports the following categories:
- Red Team (`/category/redteam`)
- Malware Dev (`/category/maldev`)
- Pen Test (`/category/pentest`)
- Mobile (`/category/mobile`)
- Exploit Dev (`/category/exploitdev`)
- Talks (`/category/talks`)
- Research (`/category/research`)

## Customization

### Configuration
Edit `_config.yml` to customize:
- Site title and description
- Author information
- Social media links
- Navigation menu

### Styling
Modify files in `_sass/` directory to customize the appearance.

### Layouts
Edit files in `_layouts/` directory to modify page layouts.

## Deployment

This blog is designed to be deployed on GitHub Pages. Simply push your changes to the `main` branch and GitHub Pages will automatically build and deploy your site.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Credits

Based on the [capt-meelo](https://github.com/capt-meelo/capt-meelo.github.io) blog template. 