from __future__ import annotations

import time
import logging
from functools import wraps
from inspect import iscoroutinefunction
from typing import Callable, Optional, Union

from fastapi import HTTPException, Request, status
from models.core import RateLimitCategory, RateLimitInterval, User, UserRateLimit
from .user import UserService

import config

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


class RateLimitService:
    def __init__(self, user_service: UserService) -> None:
        self.user_service = user_service

    @classmethod
    def get_limit(cls, category: RateLimitCategory, interval: RateLimitInterval = RateLimitInterval.minutely) -> int:
        """Returns the rate limit for a particular category + interval"""
        if interval != RateLimitInterval.minutely:
            raise NotImplementedError('Only minutely rate limits are supported')

        limits = {
            RateLimitCategory.read: config.settings.RATE_LIMIT_BY_MINUTE_READ,
            RateLimitCategory.modify: config.settings.RATE_LIMIT_BY_MINUTE_MODIFY,
            RateLimitCategory.sync: config.settings.RATE_LIMIT_BY_MINUTE_SYNC
        }
        
        if category not in limits:
            raise NotImplementedError(f'Invalid RateLimitCategory {category}')
        
        return limits[category]

    def get_current_user_limit_value(self, user: User, category: RateLimitCategory) -> int:
        """Returns the user's rate limit value, or 0 if it's expired or undefined"""
        if not user.rate_limit_map or category.value not in user.rate_limit_map:
            return 0

        # rate limit has expired, so we consider it 0
        if round(time.time()) >= user.rate_limit_map[category.value].expires:
            return 0

        return user.rate_limit_map[category.value].value

    def check_if_user_limit_expired(self, user: User, category: RateLimitCategory) -> bool:
        """Check if the user's rate limit for a category has expired"""
        if not user.rate_limit_map or category.value not in user.rate_limit_map:
            return True  # Consider expired if not set
        return round(time.time()) >= user.rate_limit_map[category.value].expires

    def verify_rate_limit(self, user: User, category: RateLimitCategory) -> None:
        """
        Updates the rate limit for a user and raises HTTP 429 if limit is exceeded
        
        Args:
            user: The user to check rate limits for
            category: The rate limit category to verify
            
        Raises:
            HTTPException: 429 if rate limit exceeded
        """
        if user.disabled or user.is_rate_limit_exempt:
            return

        rate_limit_interval_seconds = 60  # All limits are minutely
        current_time = round(time.time())
        user_limit_value = self.get_current_user_limit_value(user, category)
        limit = self.get_limit(category)

        logging.debug(f"Checking rate limit for user {user.username}: {user_limit_value}/{limit} for {category}")

        if user_limit_value >= limit:
            logger.warning(
                f"Rate limit exceeded for user {user.username}: "
                f"{user_limit_value}/{limit} requests for {category}"
            )
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "message": "Rate limit exceeded",
                    "limit": limit,
                    "current": user_limit_value,
                    "category": category.value,
                    "retry_after": user.rate_limit_map[category.value].expires - current_time
                }
            )

        # Update rate limit tracking
        new_expires = current_time + rate_limit_interval_seconds
        new_value = 1 if self.check_if_user_limit_expired(user, category) else user_limit_value + 1

        if not user.rate_limit_map:
            user.rate_limit_map = {}

        user.rate_limit_map[category.value] = UserRateLimit(
            value=new_value, 
            expires=new_expires
        )

        self.user_service.update_user(user)

        logging.debug(f"Updated rate limit for user {user.username}: {new_value}/{limit} for {category}")

    def limit(self, category: RateLimitCategory):
        """
        Decorator for rate limiting endpoints based on user
        
        Args:
            category: The rate limit category to apply
            
        Usage:
            @router.get('/endpoint')
            @rate_limit_service.limit(RateLimitCategory.read)
            async def endpoint(user: User = Depends(get_current_user)):
                ...
        """
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            async def async_wrapper(*args, **kwargs):
                user = self._extract_user_from_args(args, kwargs)
                if not user:
                    request = self._extract_request_from_args(args, kwargs)
                    if request:
                        if hasattr(request.state, 'user'):
                            user = request.state.user
                
                if not user:
                    raise ValueError(
                        f'Unable to rate limit {func.__name__}; no user provided in args or request.state'
                    )

                self.verify_rate_limit(user, category)
                return await func(*args, **kwargs)

            @wraps(func)
            def sync_wrapper(*args, **kwargs):
                user = self._extract_user_from_args(args, kwargs)
                if not user:
                    raise ValueError(
                        f'Unable to rate limit {func.__name__}; no user provided'
                    )

                self.verify_rate_limit(user, category)
                return func(*args, **kwargs)

            return async_wrapper if iscoroutinefunction(func) else sync_wrapper

        return decorator

    def _extract_user_from_args(self, args, kwargs) -> Optional[User]:
        """Extract User instance from function args or kwargs"""
        for arg in args:
            if isinstance(arg, User):
                return arg
        for val in kwargs.values():
            if isinstance(val, User):
                return val
        return None

    def _extract_request_from_args(self, args, kwargs) -> Optional[Request]:
        """Extract Request instance from function args or kwargs"""
        for arg in args:
            if isinstance(arg, Request):
                return arg
        for val in kwargs.values():
            if isinstance(val, Request):
                return val
        return None