
# Thread pool for async operations
tweet_executor = ThreadPoolExecutor(max_workers=5)

class TweetFetcher:
    def __init__(self):
        self.active_fetches = {}  # Track ongoing fetches
        self.fetch_lock = threading.Lock()
    
    async def fetch_tweets_for_user(self, cookies_dict, user_id, fetch_from_id):
        """Fetch tweets using twikit with user-specific cookies"""
        try:
            client = Client()
            
            # Create temporary cookie file for this specific fetch
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
                json.dump(cookies_dict, temp_file)
                temp_cookie_path = temp_file.name
            
            try:
                # Load cookies from temporary file
                client.load_cookies(path=temp_cookie_path)
                
                tweet_data = []
                tweets = await client.get_timeline(count=20)
                
                while tweets and len(tweet_data) < 100:
                    for tweet in tweets:
                        user = tweet.user
                        media_urls = []
                        
                        # Handle media (same logic as main.py)
                        if tweet.media:
                            for media in tweet.media:
                                if media.type == "photo":
                                    url = getattr(media, "media_url_https", None) or getattr(media, "media_url", None)
                                    if url:
                                        media_urls.append(url)
                                elif media.type in ("video", "animated_gif") and hasattr(media, "streams"):
                                    streams = media.streams or []
                                    if streams:
                                        best = streams[-1]
                                        if best.url:
                                            media_urls.append(best.url)
                        
                        profile_image_url = getattr(user, "profile_image_url_https", None) or getattr(user, "profile_image_url", None)
                        cleaned_text = re.sub(r"https://t\.co/\w+", "", tweet.full_text).strip()
                        
                        tweet_data.append({
                            "username": tweet.user.screen_name,
                            "name": tweet.user.name,
                            "verified": tweet.user.is_blue_verified,
                            "profile_image_url": profile_image_url,
                            "text": cleaned_text,
                            "tweet_id": getattr(tweet, "id", None),
                            "created_at": str(tweet.created_at),
                            "url": f"https://twitter.com/{tweet.user.screen_name}/status/{tweet.id}",
                            "media": media_urls,
                            "like_count": getattr(tweet, "favorite_count", 0),
                            "retweet_count": getattr(tweet, "retweet_count", 0),
                            "reply_count": getattr(tweet, "reply_count", 0),
                            "views": getattr(tweet, "view_count", 0)
                        })
                        
                        if len(tweet_data) >= 100:
                            break
                    
                    if len(tweet_data) >= 100:
                        break
                    
                    await asyncio.sleep(3)  # PAGE_FETCH_DELAY
                    tweets = await tweets.next()
                
                return tweet_data
                
            finally:
                # Clean up temporary cookie file
                if os.path.exists(temp_cookie_path):
                    os.unlink(temp_cookie_path)
                    
        except Exception as e:
            logger.error(f"Error fetching tweets: {e}")
            raise

# Global tweet fetcher instance
tweet_fetcher = TweetFetcher()
