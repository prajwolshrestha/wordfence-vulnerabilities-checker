# Wordfence Vulnerability Checker

A Python script that checks your WordPress plugins against the [Wordfence Intelligence v3 API](https://www.wordfence.com/help/wordfence-intelligence/) and reports any vulnerabilities published within a specified time period.

## Features

- ✅ **Interactive Date Selection** - Choose between last 7 days or a custom date range
- ✅ **Flexible Date Range** - Check vulnerabilities for any period up to 35 days
- ✅ **External Plugin List** - Manage your plugin list in a separate text file
- ✅ **Detailed Reports** - Get comprehensive vulnerability information including:
  - CVE identifiers
  - CVSS scores and severity ratings
  - Patch availability and versions
  - Direct links to detailed vulnerability reports
- ✅ **Free API Access** - Uses Wordfence's free Intelligence API

## Requirements

- Python 3.6 or higher
- `requests` library

## Installation

1. Clone this repository:
```bash
git clone https://github.com/yourusername/wordfence-vulnerability-checker.git
cd wordfence-vulnerability-checker
```

2. Install required dependencies:
```bash
pip install requests
```

## Setup

### 1. Get Your Wordfence API Key

1. Create a free account at [Wordfence.com](https://www.wordfence.com/)
2. Go to the [Integrations section](https://www.wordfence.com/account/integrations)
3. Generate an API key for the Vulnerability Data Feed
4. Copy the API key (it will only be displayed once)

### 2. Configure the Script

Open `check.py` and replace the API key on line 23:

```python
API_KEY = "YOUR_API_KEY_HERE"
```

Or set it as an environment variable:

```bash
export WORDFENCE_API_KEY="your_api_key_here"
```

### 3. Add Your Plugins

Edit the `plugins.txt` file and add your WordPress plugin slugs, one per line:

```txt
# WordPress Plugin Slugs to Check
# Lines starting with # are comments

contact-form-7
elementor
wordfence
wp-crontrol
```

**Finding Plugin Slugs:**
- The slug is the plugin's folder name in `wp-content/plugins/`
- Or the last part of the plugin's WordPress.org URL
- Example: `https://wordpress.org/plugins/contact-form-7/` → slug is `contact-form-7`

## Usage

Run the script:

```bash
python check.py
```

### Interactive Prompts

**1. Select Time Period:**
```
Select time period to check:
  1. Last 7 days (default)
  2. Custom date range

Enter your choice (1 or 2) [1]:
```

**2. For Custom Range (Option 2):**
```
Enter date range in YYYY-MM-DD format:
  From date (YYYY-MM-DD): 2024-01-01
  To date   (YYYY-MM-DD): 2024-01-31
```

### Example Output

```
✓ Loaded 20 plugin(s) from plugins.txt

Fetching vulnerability feed from Wordfence...

============================================================
WORDFENCE VULNERABILITY REPORT
Period: Last 7 days (since 2024-05-08)
============================================================

⚠️  2 vulnerability/vulnerabilities found!

[1] Contact Form 7
    Title     : Contact Form 7 < 5.9.5 - Missing Authorization
    Published : 2024-05-10 14:23:00
    CVE       : CVE-2024-1234
    CVSS      : 7.5 (High)
    Patched   : Yes — update to 5.9.5
    Action    : Update to version 5.9.5, or a newer patched version
    Details   : https://www.wordfence.com/threat-intel/vulnerabilities/id/...

[2] Elementor Pro
    Title     : Elementor Pro < 3.21.2 - Authenticated SQL Injection
    Published : 2024-05-12 09:15:00
    CVE       : CVE-2024-5678
    CVSS      : 8.1 (High)
    Patched   : Yes — update to 3.21.2
    Action    : Update to version 3.21.2, or a newer patched version
    Details   : https://www.wordfence.com/threat-intel/vulnerabilities/id/...
```

## API Rate Limits

The Wordfence Intelligence API has the following rate limits for free accounts:

- **Default**: 1 request every 30 minutes
- **Response**: `429 Too Many Requests` if exceeded

### Recommended Usage

- ✅ Run manually as needed
- ✅ Schedule daily or weekly cron jobs
- ❌ Don't run more than once every 30 minutes

**Need higher limits?** Contact Wordfence at [wfi-support@wordfence.com](mailto:wfi-support@wordfence.com) with your use case.

## Date Range Limitations

- **Maximum range**: 35 days
- **Future dates**: Not allowed
- **Format**: YYYY-MM-DD (e.g., 2024-05-15)

## File Structure

```
wordfence-vulnerability-checker/
├── check.py          # Main script
├── plugins.txt       # Your plugin list (one slug per line)
└── README.md         # This file
```

## Troubleshooting

### Invalid API Key Error
```
ERROR: Invalid API key. Get one free at https://www.wordfence.com/account/integrations
```
**Solution**: Double-check your API key in `check.py` or set the `WORDFENCE_API_KEY` environment variable.

### Rate Limited (429 Error)
```
ERROR: Rate limited. Try again later.
```
**Solution**: Wait at least 30 minutes before running the script again.

### Plugin List File Not Found
```
❌ Error: Plugin list file 'plugins.txt' not found.
```
**Solution**: Create a `plugins.txt` file in the same directory as `check.py`.

### No Plugins Found
```
❌ Error: No plugins found in 'plugins.txt'.
```
**Solution**: Add at least one plugin slug to `plugins.txt` (non-comment, non-empty line).

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool uses the [Wordfence Intelligence Vulnerability Database API](https://www.wordfence.com/help/wordfence-intelligence/). By using this script, you acknowledge that you have read and agree to the [Wordfence Intelligence Terms and Conditions](https://www.wordfence.com/wordfence-intelligence-terms-and-conditions/).

This is an independent tool and is not officially affiliated with or endorsed by Wordfence.

## Acknowledgments

- [Wordfence](https://www.wordfence.com/) for providing free access to their comprehensive WordPress vulnerability database
- The WordPress security community for their ongoing efforts to keep WordPress sites secure

## Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/wordfence-vulnerability-checker/issues)
- **Wordfence API Support**: [wfi-support@wordfence.com](mailto:wfi-support@wordfence.com)

## Changelog

### Version 2.0.0
- Added interactive date selection (last 7 days or custom range)
- Moved plugin list to external `plugins.txt` file
- Added 35-day maximum range validation
- Improved error handling and user feedback

### Version 1.0.0
- Initial release
- Basic vulnerability checking for hardcoded plugin list
- Last 7 days time period

---

**⭐ If you find this tool useful, please consider giving it a star on GitHub!**
