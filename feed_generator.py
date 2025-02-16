#!/usr/bin/env python3

"""Retrieve emails from database and convert them to an RSS feed."""

from __future__ import annotations

import datetime
import email
import email.header
import hashlib
from pathlib import Path

from feedgen.feed import FeedGenerator

import database as db
from common import logging, config
from util import (
    extract_email_address,
    extract_name_from_email,
    extract_domain_address,
    utf8_decoder,
    cleanse_content,
)


def generate_rss(sender, messages):
    """
    Generate an RSS feed for emails from a specific sender.

    Args:
        sender (str): The email sender's address.
        messages (list): A list of email messages.

    Returns:
        str: The generated RSS feed as a string.

    Raises:
        Exception: If there is an error generating the RSS feed.
    """
    def ensure_timezone(dt):
        """Ensure datetime object has timezone info."""
        if not dt.tzinfo:
            return dt.replace(tzinfo=datetime.timezone.utc)
        return dt

    try:
        channel = FeedGenerator()
        channel.link(href=f"https://{extract_domain_address(sender)}", rel="alternate")
        channel.description(f"RSS feed for {sender}")

        channel_data = {"name": sender, "pubDate": None}

        for mail_item in messages:
            msg = email.message_from_bytes(mail_item.content)
            feed_entry = channel.add_entry()

            # Process email subject
            title = email.header.make_header(email.header.decode_header(msg["subject"]))
            feed_entry.title(str(title))

            # Process links
            feed_entry.link(href=f"https://{extract_domain_address(sender)}")

            # Process dates with timezone
            dt = email.utils.parsedate_to_datetime(msg["date"])
            dt = ensure_timezone(dt)
            feed_entry.published(dt)
            feed_entry.updated(dt)

            # Update channel publication date
            if channel_data["pubDate"] is None or channel_data["pubDate"] < dt:
                channel_data["pubDate"] = dt

            # Process sender information
            channel_name = email.utils.parseaddr(msg["from"])[0]
            if channel_name:
                channel_data["name"] = channel_name

            # Generate unique GUID
            unique_string = msg["subject"] + msg["date"] + msg["from"]
            guid = hashlib.md5(unique_string.encode()).hexdigest()
            feed_entry.id(guid)

            # Process author information
            feed_entry.author(
                {
                    "name": utf8_decoder(extract_name_from_email(msg["from"])),
                    "email": extract_email_address(sender),
                }
            )

            # Process email content
            content = ""
            html_content = None
            if msg.is_multipart():
                for part in msg.walk():
                    c_type = part.get_content_type()
                    c_disp = str(part.get("Content-Disposition"))
                    if "attachment" not in c_disp:
                        charset = part.get_content_charset() or "utf-8"
                        payload = part.get_payload(decode=True)
                        if payload:
                            try:
                                decoded = payload.decode(charset, errors="ignore")
                                if c_type == "text/html":
                                    html_content = cleanse_content(decoded)
                                elif c_type == "text/plain" and html_content is None:
                                    content = cleanse_content(decoded)
                            except UnicodeDecodeError:
                                continue
            else:
                charset = msg.get_content_charset() or "utf-8"
                payload = msg.get_payload(decode=True)
                if payload:
                    try:
                        decoded = payload.decode(charset, errors="ignore")
                        if msg.get_content_type() == "text/html":
                            html_content = cleanse_content(decoded)
                        elif msg.get_content_type() == "text/plain":
                            content = cleanse_content(decoded)
                    except UnicodeDecodeError:
                        pass

            # Set entry description
            feed_entry.description(
                html_content if html_content is not None else content
            )

        # Finalize channel metadata
        channel.title(utf8_decoder(channel_data.get("name")))
        if channel_data["pubDate"]:
            channel.pubDate(ensure_timezone(channel_data["pubDate"]))

        logging.info(f"Generated RSS feed for {sender}.")
        return channel.rss_str(pretty=True).decode("utf-8")
    except Exception as e:
        logging.error(f"Failed to generate RSS feed for {sender}: {e}")
        raise


def save_feed(sender, feed_content, save_path="rss_feed"):
    """
    Saves the RSS feed content to a file.

    Args:
        sender (str): The email address of the sender.
        feed_content (str): The content of the RSS feed.

    Returns:
        str: The filename of the saved RSS feed.

    Raises:
        Exception: If there is an error while saving the RSS feed.
    """
    try:
        email_address = extract_email_address(
            sender, default="not_avail@unknown_email.com"
        )
        sanitized_email = email_address.replace("@", "_").replace(".", "_")
        output_dir = Path(save_path)
        output_dir.mkdir(parents=True, exist_ok=True)
        xml_filename = Path(f"{sanitized_email}.xml")
        save_path = output_dir / xml_filename

        with open(save_path, "w", encoding="utf-8") as f:
            f.write(feed_content)
        logging.info(f"{sender} Saved RSS feed to file: {save_path}")
        return save_path
    except Exception as e:
        logging.error(f"{sender} Failed to save RSS feed: {e}")
        raise


def main():
    """Entry point of the email to RSS feed converter."""
    data_dir = Path(config.get("data_dir"))
    data_feed_dir = data_dir / "feed"

    for sender in db.get_senders():
        messages = db.get_email(sender)
        logging.info(f"{sender} found entries={messages.count()}")
        try:
            rss_feed = generate_rss(sender, messages)
            _ = save_feed(sender, rss_feed, save_path=data_feed_dir)
        except Exception as e:
            logging.error(f"Skipping {sender} due to error: {str(e)}")
            continue


if __name__ == "__main__":
    main()
