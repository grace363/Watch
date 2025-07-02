from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils import timezone
from django.core.exceptions import ValidationError
from decimal import Decimal
import uuid
import json


class User(AbstractUser):
    """Enhanced user model for watch and earn app with anti-cheat measures"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Basic Info
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    first_name = models.CharField(max_length=50, blank=True)
    last_name = models.CharField(max_length=50, blank=True)
    
    # Financial Fields
    total_earnings = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    available_balance = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    pending_balance = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    lifetime_earnings = models.DecimalField(max_digits=12, decimal_places=2, default=0.00)
    
    # Referral System
    referral_code = models.CharField(max_length=10, unique=True, blank=True)
    referred_by = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True)
    referral_earnings = models.DecimalField(max_digits=8, decimal_places=2, default=0.00)
    total_referrals = models.PositiveIntegerField(default=0)
    
    # Activity Tracking
    is_verified = models.BooleanField(default=False)
    is_active_today = models.BooleanField(default=False)
    last_activity = models.DateTimeField(auto_now=True)
    last_login_date = models.DateTimeField(null=True, blank=True)
    session_start_time = models.DateTimeField(null=True, blank=True)
    current_session_start = models.DateTimeField(null=True, blank=True)
    last_heartbeat = models.DateTimeField(null=True, blank=True)
    
    # Daily Stats
    videos_watched_today = models.PositiveIntegerField(default=0)
    daily_online_time = models.PositiveIntegerField(default=0, help_text="Seconds online today")
    last_video_date = models.DateField(null=True, blank=True)
    last_activity_date = models.DateField(default=timezone.now)
    last_bonus_date = models.DateField(null=True, blank=True)
    last_bonus_claim = models.DateTimeField(null=True, blank=True)
    consecutive_days = models.PositiveIntegerField(default=0)
    total_daily_bonuses = models.PositiveIntegerField(default=0)
    
    # Anti-Cheat System
    cheat_violations = models.PositiveIntegerField(default=0)
    is_banned = models.BooleanField(default=False)
    ban_reason = models.TextField(blank=True)
    ban_expires_at = models.DateTimeField(null=True, blank=True)
    trust_score = models.DecimalField(max_digits=5, decimal_places=2, default=100.00)
    
    # Session Management
    session_token = models.CharField(max_length=64, blank=True)
    active_sessions_count = models.PositiveIntegerField(default=0)
    max_concurrent_sessions = models.PositiveIntegerField(default=1)
    
    # Security
    last_ip = models.GenericIPAddressField(null=True, blank=True)
    failed_login_attempts = models.PositiveIntegerField(default=0)
    account_locked_until = models.DateTimeField(null=True, blank=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.username

    def save(self, *args, **kwargs):
        if not self.referral_code:
            self.referral_code = str(uuid.uuid4())[:8].upper()
        super().save(*args, **kwargs)

    def is_account_locked(self):
        """Check if account is temporarily locked"""
        if self.account_locked_until and self.account_locked_until > timezone.now():
            return True
        return False

    def can_watch_videos(self):
        """Check if user can watch videos (not banned, verified, etc.)"""
        return (self.is_verified and 
                not self.is_banned and 
                not self.is_account_locked() and
                self.trust_score >= 50.00)

    def reset_daily_stats(self):
        """Reset daily statistics"""
        self.videos_watched_today = 0
        self.daily_online_time = 0
        self.is_active_today = False
        self.save()


class IPLog(models.Model):
    """Track user IP addresses for security"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='ip_logs')
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    action = models.CharField(max_length=50, default='login')
    country = models.CharField(max_length=100, blank=True)
    city = models.CharField(max_length=100, blank=True)
    is_suspicious = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['ip_address', 'timestamp']),
        ]

    def __str__(self):
        return f"{self.user.username} - {self.ip_address} - {self.action}"


class ContentCategory(models.Model):
    """Categories for videos/content with enhanced features"""
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    reward_multiplier = models.DecimalField(max_digits=3, decimal_places=2, default=1.00)
    min_trust_score = models.DecimalField(max_digits=5, decimal_places=2, default=0.00)
    max_daily_videos = models.PositiveIntegerField(default=50)
    is_active = models.BooleanField(default=True)
    requires_verification = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name_plural = "Content Categories"

    def __str__(self):
        return self.name


class Video(models.Model):
    """Enhanced video content model"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    video_url = models.URLField()
    thumbnail_url = models.URLField(blank=True)
    duration = models.PositiveIntegerField(help_text="Duration in seconds")
    category = models.ForeignKey(ContentCategory, on_delete=models.CASCADE)
    
    # Reward System
    base_reward = models.DecimalField(max_digits=5, decimal_places=2, default=0.01)
    bonus_reward = models.DecimalField(max_digits=5, decimal_places=2, default=0.00)
    minimum_watch_time = models.PositiveIntegerField(default=30, help_text="Minimum watch time in seconds")
    minimum_watch_percentage = models.PositiveIntegerField(default=70, help_text="Minimum watch percentage")
    
    # Restrictions
    max_views_per_user = models.PositiveIntegerField(default=1)
    cooldown_hours = models.PositiveIntegerField(default=0, help_text="Hours before user can rewatch")
    min_account_age_days = models.PositiveIntegerField(default=0)
    geographic_restrictions = models.JSONField(default=list, blank=True)
    
    # Status and Stats
    is_active = models.BooleanField(default=True)
    is_featured = models.BooleanField(default=False)
    views_count = models.PositiveIntegerField(default=0)
    unique_viewers = models.PositiveIntegerField(default=0)
    total_rewards_paid = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    
    # Quality Control
    quality_score = models.DecimalField(max_digits=3, decimal_places=2, default=5.00)
    reported_count = models.PositiveIntegerField(default=0)
    is_under_review = models.BooleanField(default=False)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    expires_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.title

    @property
    def calculated_reward(self):
        """Calculate total reward including bonus"""
        base = self.base_reward * self.category.reward_multiplier
        return base + self.bonus_reward

    @property
    def minimum_watch_seconds(self):
        """Calculate minimum watch time based on percentage or fixed time"""
        percentage_time = (self.duration * self.minimum_watch_percentage) // 100
        return max(self.minimum_watch_time, percentage_time)

    def can_user_watch(self, user):
        """Check if user can watch this video"""
        if not self.is_active or (self.expires_at and self.expires_at < timezone.now()):
            return False, "Video not available"
        
        if user.trust_score < self.category.min_trust_score:
            return False, "Trust score too low"
        
        # Check if user has already watched maximum times
        watch_count = WatchSession.objects.filter(
            user=user, 
            video=self,
            is_completed=True
        ).count()
        
        if watch_count >= self.max_views_per_user:
            return False, "Maximum views reached"
        
        # Check cooldown
        if self.cooldown_hours > 0:
            last_watch = WatchSession.objects.filter(
                user=user,
                video=self,
                is_completed=True
            ).order_by('-end_time').first()
            
            if last_watch:
                cooldown_end = last_watch.end_time + timezone.timedelta(hours=self.cooldown_hours)
                if timezone.now() < cooldown_end:
                    return False, f"Cooldown active until {cooldown_end}"
        
        return True, "OK"


class WatchSession(models.Model):
    """Enhanced watch session tracking with anti-cheat"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    video = models.ForeignKey(Video, on_delete=models.CASCADE)
    
    # Session Timing
    start_time = models.DateTimeField(auto_now_add=True)
    end_time = models.DateTimeField(null=True, blank=True)
    duration_watched = models.PositiveIntegerField(default=0, help_text="Duration watched in seconds")
    watch_percentage = models.DecimalField(max_digits=5, decimal_places=2, default=0.00)
    
    # Status
    is_completed = models.BooleanField(default=False)
    is_valid = models.BooleanField(default=True)
    reward_earned = models.DecimalField(max_digits=5, decimal_places=2, default=0.00)
    reward_paid = models.BooleanField(default=False)
    
    # Anti-Cheat Data
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    heartbeat_count = models.PositiveIntegerField(default=0)
    tab_switches = models.PositiveIntegerField(default=0)
    play_speed_changes = models.PositiveIntegerField(default=0)
    suspicious_activity = models.JSONField(default=dict, blank=True)
    
    # Quality Metrics
    average_playback_speed = models.DecimalField(max_digits=3, decimal_places=2, default=1.00)
    interaction_count = models.PositiveIntegerField(default=0)
    volume_changes = models.PositiveIntegerField(default=0)
    
    # Validation
    is_flagged = models.BooleanField(default=False)
    flag_reason = models.TextField(blank=True)
    reviewed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='reviewed_sessions')
    reviewed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=['user', 'start_time']),
            models.Index(fields=['video', 'start_time']),
            models.Index(fields=['is_completed', 'reward_paid']),
        ]

    def __str__(self):
        return f"{self.user.username} - {self.video.title}"

    def clean(self):
        """Validate watch session data"""
        if self.duration_watched > self.video.duration + 30:  # 30 second buffer
            raise ValidationError("Watch duration cannot exceed video duration")
        
        if self.watch_percentage > 100:
            raise ValidationError("Watch percentage cannot exceed 100%")

    def calculate_watch_percentage(self):
        """Calculate and update watch percentage"""
        if self.video.duration > 0:
            self.watch_percentage = (self.duration_watched / self.video.duration) * 100
        return self.watch_percentage

    def is_eligible_for_reward(self):
        """Check if session is eligible for reward"""
        if not self.is_valid or self.is_flagged:
            return False
        
        min_watch_time = self.video.minimum_watch_seconds
        return (self.duration_watched >= min_watch_time and 
                self.watch_percentage >= self.video.minimum_watch_percentage)

    def save(self, *args, **kwargs):
        # Calculate watch percentage
        self.calculate_watch_percentage()
        
        # Check completion and award reward
        if (self.is_eligible_for_reward() and 
            not self.is_completed and 
            not self.reward_paid):
            
            self.is_completed = True
            self.reward_earned = self.video.calculated_reward
            
            # Create transaction record
            Transaction.objects.create(
                user=self.user,
                transaction_type='WATCH_REWARD',
                amount=self.reward_earned,
                description=f"Watched: {self.video.title}",
                reference_id=str(self.id),
                status='PENDING'
            )
            
        super().save(*args, **kwargs)


class DailyReward(models.Model):
    """Enhanced daily login rewards with streaks"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    date = models.DateField(default=timezone.now)
    
    # Requirements
    online_duration = models.PositiveIntegerField(default=0, help_text="Time spent online in seconds")
    required_duration = models.PositiveIntegerField(default=300, help_text="Required 5 minutes online")
    videos_watched = models.PositiveIntegerField(default=0)
    required_videos = models.PositiveIntegerField(default=3)
    
    # Reward Details
    base_reward = models.DecimalField(max_digits=5, decimal_places=2, default=0.05)
    streak_bonus = models.DecimalField(max_digits=5, decimal_places=2, default=0.00)
    total_reward = models.DecimalField(max_digits=5, decimal_places=2, default=0.05)
    
    # Status
    requirements_met = models.BooleanField(default=False)
    is_claimed = models.BooleanField(default=False)
    claimed_at = models.DateTimeField(null=True, blank=True)
    
    # Streak Info
    consecutive_days = models.PositiveIntegerField(default=1)
    is_streak_day = models.BooleanField(default=True)
    
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ['user', 'date']
        indexes = [
            models.Index(fields=['user', 'date']),
            models.Index(fields=['date', 'is_claimed']),
        ]

    def __str__(self):
        return f"{self.user.username} - {self.date}"

    def calculate_streak_bonus(self):
        """Calculate bonus based on consecutive days"""
        if self.consecutive_days >= 30:
            self.streak_bonus = self.base_reward * 2.0  # 200% bonus
        elif self.consecutive_days >= 14:
            self.streak_bonus = self.base_reward * 1.0  # 100% bonus
        elif self.consecutive_days >= 7:
            self.streak_bonus = self.base_reward * 0.5  # 50% bonus
        else:
            self.streak_bonus = 0.00
        
        self.total_reward = self.base_reward + self.streak_bonus

    def check_requirements(self):
        """Check if all requirements are met"""
        self.requirements_met = (
            self.online_duration >= self.required_duration and
            self.videos_watched >= self.required_videos
        )
        return self.requirements_met

    def can_claim_reward(self):
        """Check if user can claim daily reward"""
        return (self.check_requirements() and 
                not self.is_claimed and 
                not self.user.is_banned)

    def claim_reward(self):
        """Claim daily reward and update user balance"""
        if self.can_claim_reward():
            self.calculate_streak_bonus()
            self.is_claimed = True
            self.claimed_at = timezone.now()
            
            # Update user earnings
            self.user.total_earnings += self.total_reward
            self.user.available_balance += self.total_reward
            self.user.total_daily_bonuses += 1
            self.user.consecutive_days = self.consecutive_days
            self.user.last_bonus_claim = timezone.now()
            self.user.save()
            
            # Create transaction record
            Transaction.objects.create(
                user=self.user,
                transaction_type='DAILY_REWARD',
                amount=self.total_reward,
                description=f"Daily reward - Day {self.consecutive_days}",
                reference_id=str(self.id)
            )
            
            self.save()
            return True
        return False


class Transaction(models.Model):
    """Enhanced transaction logging"""
    TRANSACTION_TYPES = [
        ('WATCH_REWARD', 'Watch Reward'),
        ('DAILY_REWARD', 'Daily Login Reward'),
        ('REFERRAL_BONUS', 'Referral Bonus'),
        ('STREAK_BONUS', 'Streak Bonus'),
        ('ADMIN_BONUS', 'Admin Bonus'),
        ('WITHDRAWAL', 'Withdrawal'),
        ('WITHDRAWAL_FEE', 'Withdrawal Fee'),
        ('REFUND', 'Refund'),
        ('PENALTY', 'Penalty'),
        ('CORRECTION', 'Balance Correction'),
    ]
    
    TRANSACTION_STATUS = [
        ('PENDING', 'Pending'),
        ('PROCESSING', 'Processing'),
        ('COMPLETED', 'Completed'),
        ('FAILED', 'Failed'),
        ('CANCELLED', 'Cancelled'),
        ('REVERSED', 'Reversed'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    transaction_type = models.CharField(max_length=20, choices=TRANSACTION_TYPES)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    fee = models.DecimalField(max_digits=8, decimal_places=2, default=0.00)
    net_amount = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(max_length=20, choices=TRANSACTION_STATUS, default='PENDING')
    
    # Additional Info
    description = models.TextField(blank=True)
    reference_id = models.CharField(max_length=100, blank=True)
    external_reference = models.CharField(max_length=100, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    
    # Processing Info
    processed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='processed_transactions')
    processed_at = models.DateTimeField(null=True, blank=True)
    failure_reason = models.TextField(blank=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'transaction_type', 'created_at']),
            models.Index(fields=['status', 'created_at']),
            models.Index(fields=['reference_id']),
        ]

    def __str__(self):
        return f"{self.user.username} - {self.transaction_type} - {self.amount}"

    def save(self, *args, **kwargs):
        # Calculate net amount
        if self.amount >= 0:  # Credit
            self.net_amount = self.amount - self.fee
        else:  # Debit
            self.net_amount = self.amount - self.fee
        
        super().save(*args, **kwargs)

class UserStats(models.Model):
    """Enhanced daily user statistics"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    date = models.DateField(default=timezone.now)
    
    # Daily Activity
    videos_watched = models.PositiveIntegerField(default=0)
    total_watch_time = models.PositiveIntegerField(default=0, help_text="Total watch time in seconds")
    online_duration = models.PositiveIntegerField(default=0, help_text="Time spent online in seconds")
    sessions_count = models.PositiveIntegerField(default=0)
    
    # Earnings
    daily_earnings = models.DecimalField(max_digits=8, decimal_places=2, default=0.00)
    watch_rewards = models.DecimalField(max_digits=8, decimal_places=2, default=0.00)
    bonus_rewards = models.DecimalField(max_digits=8, decimal_places=2, default=0.00)
    referral_earnings = models.DecimalField(max_digits=8, decimal_places=2, default=0.00)
    
    # Engagement Metrics
    completed_sessions = models.PositiveIntegerField(default=0)
    invalid_sessions = models.PositiveIntegerField(default=0)
    flagged_sessions = models.PositiveIntegerField(default=0)
    average_watch_percentage = models.DecimalField(max_digits=5, decimal_places=2, default=0.00)
    
    # Referral Activity
    new_referrals = models.PositiveIntegerField(default=0)
    active_referrals = models.PositiveIntegerField(default=0)
    
    # Quality Metrics
    trust_score_change = models.DecimalField(max_digits=5, decimal_places=2, default=0.00)
    violations_count = models.PositiveIntegerField(default=0)
    
    # Streaks
    is_streak_day = models.BooleanField(default=False)
    consecutive_days = models.PositiveIntegerField(default=0)
    
    # Login/Activity
    first_login = models.DateTimeField(null=True, blank=True)
    last_activity = models.DateTimeField(null=True, blank=True)
    login_count = models.PositiveIntegerField(default=0)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ['user', 'date']
        ordering = ['-date']
        indexes = [
            models.Index(fields=['user', 'date']),
            models.Index(fields=['date', 'daily_earnings']),
            models.Index(fields=['user', 'consecutive_days']),
        ]

    def __str__(self):
        return f"{self.user.username} - {self.date}"

    def calculate_completion_rate(self):
        """Calculate session completion rate"""
        total_sessions = self.completed_sessions + self.invalid_sessions
        if total_sessions > 0:
            return (self.completed_sessions / total_sessions) * 100
        return 0.00

    def update_daily_stats(self):
        """Update daily statistics from related models"""
        # Get today's watch sessions
        today_sessions = WatchSession.objects.filter(
            user=self.user,
            start_time__date=self.date
        )
        
        self.videos_watched = today_sessions.count()
        self.completed_sessions = today_sessions.filter(is_completed=True).count()
        self.invalid_sessions = today_sessions.filter(is_valid=False).count()
        self.flagged_sessions = today_sessions.filter(is_flagged=True).count()
        
        # Calculate total watch time
        self.total_watch_time = sum(
            session.duration_watched for session in today_sessions
        )
        
        # Calculate average watch percentage
        if today_sessions.exists():
            self.average_watch_percentage = today_sessions.aggregate(
                avg_percentage=models.Avg('watch_percentage')
            )['avg_percentage'] or 0.00
        
        # Get today's transactions
        today_transactions = Transaction.objects.filter(
            user=self.user,
            created_at__date=self.date,
            status='COMPLETED'
        )
        
        self.watch_rewards = today_transactions.filter(
            transaction_type='WATCH_REWARD'
        ).aggregate(
            total=models.Sum('amount')
        )['total'] or 0.00
        
        self.bonus_rewards = today_transactions.filter(
            transaction_type__in=['DAILY_REWARD', 'STREAK_BONUS']
        ).aggregate(
            total=models.Sum('amount')
        )['total'] or 0.00
        
        self.referral_earnings = today_transactions.filter(
            transaction_type='REFERRAL_BONUS'
        ).aggregate(
            total=models.Sum('amount')
        )['total'] or 0.00
        
        self.daily_earnings = self.watch_rewards + self.bonus_rewards + self.referral_earnings
        
        self.save()


# Additional models that might be useful for the complete system

class WithdrawalRequest(models.Model):
    """Handle withdrawal requests"""
    WITHDRAWAL_METHODS = [
        ('BANK', 'Bank Transfer'),
        ('PAYPAL', 'PayPal'),
        ('MOBILE_MONEY', 'Mobile Money'),
        ('CRYPTO', 'Cryptocurrency'),
    ]
    
    WITHDRAWAL_STATUS = [
        ('PENDING', 'Pending'),
        ('APPROVED', 'Approved'),
        ('PROCESSING', 'Processing'),
        ('COMPLETED', 'Completed'),
        ('REJECTED', 'Rejected'),
        ('CANCELLED', 'Cancelled'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    fee = models.DecimalField(max_digits=8, decimal_places=2, default=0.00)
    net_amount = models.DecimalField(max_digits=10, decimal_places=2)
    
    withdrawal_method = models.CharField(max_length=20, choices=WITHDRAWAL_METHODS)
    payment_details = models.JSONField(default=dict)
    
    status = models.CharField(max_length=20, choices=WITHDRAWAL_STATUS, default='PENDING')
    admin_notes = models.TextField(blank=True)
    
    processed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='processed_withdrawals')
    processed_at = models.DateTimeField(null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.user.username} - {self.amount} - {self.status}"


class SystemSettings(models.Model):
    """System-wide settings"""
    key = models.CharField(max_length=100, unique=True)
    value = models.TextField()
    data_type = models.CharField(max_length=20, choices=[
        ('STRING', 'String'),
        ('INTEGER', 'Integer'),
        ('DECIMAL', 'Decimal'),
        ('BOOLEAN', 'Boolean'),
        ('JSON', 'JSON'),
    ], default='STRING')
    description = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.key

    def get_value(self):
        """Get typed value"""
        if self.data_type == 'INTEGER':
            return int(self.value)
        elif self.data_type == 'DECIMAL':
            return Decimal(self.value)
        elif self.data_type == 'BOOLEAN':
            return self.value.lower() in ('true', '1', 'yes')
        elif self.data_type == 'JSON':
            return json.loads(self.value)
        return self.value
   

#==== Util: Send Email ====

def send_email(to, subject, body, html_body=None): 
    """Send email with both text and HTML versions"""
    try:
        msg = Message(
            subject=subject, 
            recipients=[to], 
            body=body, 
            html=html_body,
            sender=app.config['MAIL_USERNAME']
        ) 
        mail.send(msg)
        return True
    except Exception as e:
        print(f"❌ Failed to send email to {to}: {str(e)}")
        return False

def create_verification_email(email, verification_link):
    """Create professional verification email content"""
    
    # Plain text version
    text_body = f"""
Welcome to Watch & Earn!

Thank you for creating your account. To complete your registration and start earning, please verify your email address by clicking the link below:

{verification_link}

This verification link will expire in 1 hour for security reasons.

If you did not create this account, please ignore this email.

Best regards,
The Watch & Earn Team
    """
    
    # HTML version
    html_body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
            .content {{ background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }}
            .button {{ background: #4CAF50; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 20px 0; }}
            .footer {{ color: #666; font-size: 12px; margin-top: 20px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🎬 Welcome to Watch & Earn!</h1>
                <p>Verify your email to start earning</p>
            </div>
            <div class="content">
                <h2>Hello!</h2>
                <p>Thank you for joining Watch & Earn. You're one step away from starting to earn money by watching videos!</p>
                
                <p>Please click the button below to verify your email address:</p>
                
                <a href="{verification_link}" class="button">✅ Verify My Email</a>
                
                <p>Or copy and paste this link into your browser:</p>
                <p style="word-break: break-all; background: #eee; padding: 10px; border-radius: 5px;">
                    {verification_link}
                </p>
                
                <div class="footer">
                    <p>⏰ This link expires in 1 hour</p>
                    <p>🔒 If you didn't create this account, please ignore this email</p>
                    <p>💰 Start earning today with Watch & Earn!</p>
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    
    return text_body, html_body

#==== Routes ====

@app.route('/') 
def home(): 
    if MAINTENANCE_MODE: 
        return "Site is under maintenance. Please check back later." 
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST']) 
def register(): 
    if request.method == 'POST': 
        email = request.form['email'] 
        password = request.form['password'] 
        confirm = request.form.get('confirm_password') 
        role = request.form['account_type']

        if PASSWORD_CONFIRMATION_REQUIRED and password != confirm:
            return jsonify({'error': 'Passwords do not match'}), 400

        if len(password) < PASSWORD_MIN_LENGTH:
            return jsonify({'error': f'Password must be at least {PASSWORD_MIN_LENGTH} characters'}), 400

        if role not in ALLOWED_ROLES:
            return jsonify({'error': 'Invalid account type'}), 400

        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already exists'}), 409

        hashed = generate_password_hash(password)
        user = User(
            email=email, 
            password_hash=hashed, 
            account_type=role,
            last_ip=get_client_ip() if ENABLE_IP_TRACKING else None
        )
        db.session.add(user)
        db.session.commit()

        # Log registration IP
        log_user_ip(user.id, "register")

        token = serializer.dumps(email, salt='email-confirm')
        link = url_for('confirm_email', token=token, _external=True)
        
        # Create professional email content
        text_body, html_body = create_verification_email(email, link)
        
        # Send verification email
        email_sent = send_email(
            email, 
            '🎬 Verify Your Watch & Earn Account', 
            text_body, 
            html_body
        )
        
        if not email_sent:
            return jsonify({'error': 'Failed to send verification email. Please try again.'}), 500

        if AUTO_LOGIN_AFTER_REGISTRATION:
            session['user_id'] = user.id
            session['account_type'] = user.account_type
            return redirect(url_for('youtuber_dashboard' if user.account_type == 'YouTuber' else 'user_dashboard'))

        return jsonify({
            'success': True,
            'message': '🎉 Account created successfully! Please check your email to verify your account.',
            'email_sent': True
        })

    return render_template('register.html')

@app.route('/edit_profile')
def edit_profile():
    """Display the edit profile page"""
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if not user:
        return redirect(url_for('logout'))

    return render_template('edit_profile.html', user=user)

# Add this route for handling profile updates
@app.route('/update_profile', methods=['POST'])
def update_profile():
    """Handle profile update requests"""
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Login required'}), 401

    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        action = request.form.get('action')
        
        if action == 'update_basic':
            # Update basic information
            user.first_name = request.form.get('first_name', '').strip()
            user.last_name = request.form.get('last_name', '').strip()
            user.phone = request.form.get('phone', '').strip()
            
            db.session.commit()
            log_user_ip(user_id, "profile_update_basic")
            
            return jsonify({
                'success': True,
                'message': 'Basic information updated successfully!'
            })
        
        elif action == 'update_settings':
            # Update account settings
            new_account_type = request.form.get('account_type')
            
            if new_account_type not in ALLOWED_ROLES:
                return jsonify({'error': 'Invalid account type'}), 400
            
            old_type = user.account_type
            user.account_type = new_account_type
            session['account_type'] = new_account_type
            
            db.session.commit()
            log_user_ip(user_id, f"account_type_change_{old_type}_to_{new_account_type}")
            
            # Determine redirect URL
            dashboard_url = url_for('youtuber_dashboard') if new_account_type == 'YouTuber' else url_for('user_dashboard')
            
            return jsonify({
                'success': True,
                'message': f'Account type changed to {new_account_type}!',
                'redirect': dashboard_url
            })
        
        elif action == 'change_password':
            # Change password
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            
            # Validate current password
            if not check_password_hash(user.password_hash, current_password):
                return jsonify({'error': 'Current password is incorrect'}), 400
            
            # Validate new password
            if len(new_password) < PASSWORD_MIN_LENGTH:
                return jsonify({'error': f'Password must be at least {PASSWORD_MIN_LENGTH} characters long'}), 400
            
            if PASSWORD_CONFIRMATION_REQUIRED and new_password != confirm_password:
                return jsonify({'error': 'New passwords do not match'}), 400
            
            # Update password
            user.password_hash = generate_password_hash(new_password)
            db.session.commit()
            log_user_ip(user_id, "password_change")
            
            return jsonify({
                'success': True,
                'message': 'Password updated successfully!'
            })
        
        else:
            return jsonify({'error': 'Invalid action'}), 400
            
    except Exception as e:
        print(f"❌ Profile update error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'An error occurred while updating profile'}), 500

# Also update your existing profile route to handle the new fields
@app.route('/profile')
def profile():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if not user:
        return redirect(url_for('logout'))

    return render_template('profile.html', user=user)

@app.route('/verify/<token>') 
def confirm_email(token): 
    try: 
        email = serializer.loads(token, salt='email-confirm', max_age=3600) 
    except SignatureExpired: 
        return '''
        <div style="text-align: center; padding: 50px; font-family: Arial;">
            <h2>⏰ Verification Link Expired</h2>
            <p>Your verification link has expired for security reasons.</p>
            <p><a href="/resend-verification" style="color: #4CAF50;">Request a new verification email</a></p>
            <p><a href="/login" style="color: #2196F3;">Back to Login</a></p>
        </div>
        ''', 400 
    except BadSignature: 
        return '''
        <div style="text-align: center; padding: 50px; font-family: Arial;">
            <h2>❌ Invalid Verification Link</h2>
            <p>This verification link is invalid or has been tampered with.</p>
            <p><a href="/register" style="color: #4CAF50;">Create New Account</a></p>
            <p><a href="/login" style="color: #2196F3;">Back to Login</a></p>
        </div>
        ''', 400

    user = User.query.filter_by(email=email).first()
    if user:
        if user.is_verified:
            return '''
            <div style="text-align: center; padding: 50px; font-family: Arial;">
                <h2>✅ Already Verified</h2>
                <p>Your email has already been verified!</p>
                <p><a href="/login" style="color: #4CAF50; padding: 10px 20px; background: #f0f0f0; text-decoration: none; border-radius: 5px;">Login to Your Account</a></p>
            </div>
            ''', 200
        else:
            user.is_verified = True
            db.session.commit()
            
            # Log email verification
            log_user_ip(user.id, "email_verify")
            
            return '''
            <div style="text-align: center; padding: 50px; font-family: Arial;">
                <h2>🎉 Email Verified Successfully!</h2>
                <p>Welcome to Watch & Earn! Your account is now active.</p>
                <p>You can now start watching videos and earning money!</p>
                <p><a href="/login" style="color: white; padding: 15px 30px; background: #4CAF50; text-decoration: none; border-radius: 5px; display: inline-block; margin-top: 20px;">🚀 Start Earning Now</a></p>
            </div>
            ''', 200
    return '''
    <div style="text-align: center; padding: 50px; font-family: Arial;">
        <h2>❌ User Not Found</h2>
        <p>We couldn't find an account associated with this verification link.</p>
        <p><a href="/register" style="color: #4CAF50;">Create New Account</a></p>
    </div>
    ''', 404

@app.route('/login', methods=['GET', 'POST']) 
@limiter.limit(LOGIN_RATE_LIMIT) 
def login(): 
    if request.method == 'POST': 
        try:
            # Get form data
            email = request.form.get('email')
            password = request.form.get('password')
            
            # Validate input
            if not email or not password:
                return jsonify({'error': 'Email and password are required'}), 400
            
            # Find user
            user = User.query.filter_by(email=email).first()
            if not user: 
                return jsonify({'error': 'Invalid email or password'}), 401
            
            # Check password
            if not check_password_hash(user.password_hash, password): 
                return jsonify({'error': 'Invalid email or password'}), 401
            
            # Check if email is verified
            if not user.is_verified: 
                return jsonify({
                    'error': 'Please verify your email first.',
                    'needs_verification': True
                }), 403
            
            # Update IP tracking (with error handling)
            try:
                current_ip = get_client_ip()
                if ENABLE_IP_TRACKING:
                    user.last_ip = current_ip
                    log_user_ip(user.id, "login")
            except Exception as ip_error:
                print(f"⚠️ IP tracking failed: {str(ip_error)}")
                # Continue with login even if IP tracking fails
            
            # Set session data
            session.permanent = True  # Make session permanent
            session['user_id'] = user.id
            session['account_type'] = user.account_type
            session['email'] = user.email
            
            # Update last login (with error handling)
            try:
                user.last_login_date = datetime.utcnow()
                db.session.commit()
            except Exception as db_error:
                print(f"⚠️ Database update failed: {str(db_error)}")
                db.session.rollback()
                # Don't fail login if just the timestamp update fails
            
            # Return success response with redirect URL
            dashboard_url = url_for('youtuber_dashboard') if user.account_type == 'YouTuber' else url_for('user_dashboard')
            
            return jsonify({
                'success': True,
                'message': 'Login successful!',
                'redirect': dashboard_url,
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'account_type': user.account_type
                }
            }), 200
            
        except Exception as e:
            print(f"❌ Login error: {str(e)}")
            db.session.rollback()
            return jsonify({'error': 'An internal error occurred. Please try again.'}), 500

    return render_template('login.html')

# This integrates with your existing Flask app structure
# No need to redefine imports or mail config since you already have them

# Replace your existing forgot password routes with these fixed versions:

# Fixed forgot password route - replace your existing one

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """Handle both display and submission of forgot password form"""
    if request.method == 'GET':
        return render_template('forgot_password.html')
    
    # POST method - handle form submission
    try:
        email = request.form.get('email', '').strip().lower()
        
        if not email:
            return jsonify({'error': 'Email address is required'}), 400
        
        if '@' not in email or '.' not in email:
            return jsonify({'error': 'Please enter a valid email address'}), 400
        
        # Check if user exists in database
        user = User.query.filter_by(email=email).first()
        
        # Always return success message (don't reveal if email exists)
        success_message = 'If an account with this email exists, a password reset link has been sent.'
        
        if user and user.is_verified:
            # Generate reset token using your existing serializer
            reset_token = serializer.dumps(email, salt='password-reset')
            reset_link = url_for('reset_password', token=reset_token, _external=True)
            
            # Create professional reset email content
            text_body = f"""
Password Reset Request - Watch & Earn

You requested a password reset for your Watch & Earn account.

Click the link below to reset your password:
{reset_link}

This link will expire in 1 hour for security reasons.

If you did not request this password reset, please ignore this email and your password will remain unchanged.

Best regards,
The Watch & Earn Team
            """
            
            html_body = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                    .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                    .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
                    .content {{ background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }}
                    .button {{ background: #ff6b6b; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 20px 0; }}
                    .footer {{ color: #666; font-size: 12px; margin-top: 20px; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🔒 Password Reset Request</h1>
                        <p>Reset your Watch & Earn password</p>
                    </div>
                    <div class="content">
                        <h2>Hello!</h2>
                        <p>You requested a password reset for your Watch & Earn account.</p>
                        
                        <p>Click the button below to reset your password:</p>
                        
                        <a href="{reset_link}" class="button">🔑 Reset My Password</a>
                        
                        <p>Or copy and paste this link into your browser:</p>
                        <p style="word-break: break-all; background: #eee; padding: 10px; border-radius: 5px;">
                            {reset_link}
                        </p>
                        
                        <div class="footer">
                            <p>⏰ This link expires in 1 hour</p>
                            <p>🔒 If you didn't request this reset, please ignore this email</p>
                            <p>💰 Watch & Earn Team</p>
                        </div>
                    </div>
                </div>
            </body>
            </html>
            """
            
            # Send password reset email
            email_sent = send_email(
                email, 
                '🔒 Reset Your Watch & Earn Password', 
                text_body, 
                html_body
            )
            
            if not email_sent:
                print(f"❌ Failed to send password reset email to {email}")
                return jsonify({'error': 'Unable to send reset email. Please try again later.'}), 500
            
            print(f"✅ Password reset email sent successfully to {email}")
        
        # Always return success (security best practice)
        return jsonify({
            'success': True,
            'message': success_message
        }), 200
        
    except Exception as e:
        print(f"❌ Forgot password error: {str(e)}")
        return jsonify({'error': 'An internal error occurred. Please try again.'}), 500


# You also need this route to handle the actual password reset
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Handle password reset with token"""
    try:
        # Verify the reset token
        email = serializer.loads(token, salt='password-reset', max_age=3600)  # 1 hour expiry
    except SignatureExpired:
        return '''
        <div style="text-align: center; padding: 50px; font-family: Arial;">
            <h2>⏰ Reset Link Expired</h2>
            <p>Your password reset link has expired for security reasons.</p>
            <p><a href="/forgot_password" style="color: #4CAF50;">Request a new reset link</a></p>
            <p><a href="/login" style="color: #2196F3;">Back to Login</a></p>
        </div>
        ''', 400
    except BadSignature:
        return '''
        <div style="text-align: center; padding: 50px; font-family: Arial;">
            <h2>❌ Invalid Reset Link</h2>
            <p>This password reset link is invalid or has been tampered with.</p>
            <p><a href="/forgot_password" style="color: #4CAF50;">Request a new reset link</a></p>
            <p><a href="/login" style="color: #2196F3;">Back to Login</a></p>
        </div>
        ''', 400
    
    user = User.query.filter_by(email=email).first()
    if not user:
        return '''
        <div style="text-align: center; padding: 50px; font-family: Arial;">
            <h2>❌ User Not Found</h2>
            <p>We couldn't find an account associated with this reset link.</p>
            <p><a href="/register" style="color: #4CAF50;">Create New Account</a></p>
        </div>
        ''', 404
    
    if request.method == 'POST':
        new_password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not new_password or len(new_password) < PASSWORD_MIN_LENGTH:
            flash(f'Password must be at least {PASSWORD_MIN_LENGTH} characters long', 'error')
            return render_template('reset_password.html', token=token)
        
        if PASSWORD_CONFIRMATION_REQUIRED and new_password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('reset_password.html', token=token)
        
        # Update password
        user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        
        # Log password reset
        log_user_ip(user.id, "password_reset")
        
        flash('Password reset successfully! You can now login with your new password.', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)

# Remove this since you already have CSRF token generation in your code
# @app.context_processor
# def inject_csrf_token():
#     if 'csrf_token' not in session:
#         session['csrf_token'] = secrets.token_hex(16)
#     return dict(csrf_token=session['csrf_token'])

@app.route('/switch-account-type', methods=['POST'])
def switch_account_type():
    """Allow users to switch between User and YouTuber account types"""
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Login required'}), 401
    
    try:
        new_account_type = request.form.get('account_type')
        
        # Validate account type
        if new_account_type not in ALLOWED_ROLES:
            return jsonify({'error': 'Invalid account type'}), 400
        
        # Get user
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Check if already the same type
        if user.account_type == new_account_type:
            return jsonify({'message': f'Already a {new_account_type}'}), 200
        
        # Update account type
        old_type = user.account_type
        user.account_type = new_account_type
        session['account_type'] = new_account_type
        
        db.session.commit()
        
        # Log the account type change
        log_user_ip(user.id, f"account_switch_{old_type}_to_{new_account_type}")
        
        # Determine redirect URL
        dashboard_url = url_for('youtuber_dashboard') if new_account_type == 'YouTuber' else url_for('user_dashboard')
        
        return jsonify({
            'success': True,
            'message': f'Successfully switched to {new_account_type} account!',
            'redirect': dashboard_url,
            'old_type': old_type,
            'new_type': new_account_type
        }), 200
        
    except Exception as e:
        print(f"❌ Account switch error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to switch account type. Please try again.'}), 500

@app.route('/user_dashboard') 
def user_dashboard(): 
    if session.get('account_type') != 'User': 
        return 'Access denied', 403 
    return render_template('user_dashboard.html')

@app.route('/youtuber_dashboard') 
def youtuber_dashboard(): 
    if session.get('account_type') != 'YouTuber': 
        return 'Access denied', 403 
    return render_template('youtuber_dashboard.html')

@app.route('/watch', methods=['POST']) 
def track_watch(): 
    if not ENABLE_REWARDS: 
        return jsonify({'message': 'Rewards are currently disabled'})

    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Login required'}), 401
    
    watch_time = int(request.form.get('seconds_watched', 0))
    
    if watch_time >= 30:
        user = User.query.get(user_id)
        user.total_watch_minutes += watch_time // 60
        user.balance_usd += (watch_time / 60) * 0.01
        db.session.commit()
        
        # Log watch activity
        log_user_ip(user_id, f"watch_{watch_time}s")
        
        return jsonify({'message': 'Watch time tracked and rewarded'})
    return jsonify({'message': 'Watch time too short'})

@app.route('/daily-bonus', methods=['POST']) 
def give_daily_bonus(): 
    user_id = session.get('user_id') 
    if not user_id: 
        return jsonify({'error': 'Login required'}), 401 
    user = User.query.get(user_id) 
    now = datetime.utcnow() 
    if user.last_login_date is None or (now - user.last_login_date).days >= 1: 
        user.balance_usd += DAILY_REWARD 
        user.last_login_date = now 
        db.session.commit() 
        
        # Log daily bonus claim
        log_user_ip(user_id, "daily_bonus")
        
        return jsonify({'message': 'Daily bonus granted'}) 
    return jsonify({'message': 'Already claimed today'})

@app.route('/withdraw', methods=['POST']) 
def withdraw(): 
    user_id = session.get('user_id') 
    amount = float(request.form.get('amount')) 
    user = User.query.get(user_id) 
    if user.balance_usd >= MIN_WITHDRAW_AMOUNT and amount <= user.balance_usd: 
        req = WithdrawalRequest(user_id=user.id, amount=amount, status='pending') 
        user.balance_usd -= amount 
        db.session.add(req) 
        db.session.commit() 
        
        # Log withdrawal request
        log_user_ip(user_id, f"withdrawal_${amount}")
        
        return jsonify({'message': 'Withdrawal request submitted'}) 
    return jsonify({'error': f'Minimum withdrawal is ${MIN_WITHDRAW_AMOUNT} or insufficient balance'})

@app.route('/admin/panel') 
def admin_panel(): 
    users = User.query.all() 
    withdrawals = WithdrawalRequest.query.all() 
    videos = Video.query.all() 
    
    # Get IP tracking data if enabled
    ip_logs = []
    if ENABLE_IP_TRACKING:
        ip_logs = IPLog.query.order_by(IPLog.timestamp.desc()).limit(100).all()
    
    return render_template('admin_panel.html', 
                         users=users, 
                         withdrawals=withdrawals, 
                         videos=videos,
                         ip_logs=ip_logs,
                         ip_tracking_enabled=ENABLE_IP_TRACKING)

@app.route('/admin/user-ips/<int:user_id>')
def get_user_ip_history(user_id):
    """Get IP history for a specific user (admin only)"""
    if not ENABLE_IP_TRACKING:
        return jsonify({'error': 'IP tracking is disabled'}), 400
    
    # Note: Add admin authentication here in production
    ip_logs = IPLog.query.filter_by(user_id=user_id)\
        .order_by(IPLog.timestamp.desc())\
        .limit(50)\
        .all()
    
    logs_data = [{
        'ip_address': log.ip_address,
        'action': log.action,
        'timestamp': log.timestamp.isoformat(),
        'user_agent': log.user_agent
    } for log in ip_logs]
    
    return jsonify({'ip_logs': logs_data})

@app.route('/upload_video', methods=['POST']) 
def upload_video(): 
    if session.get('account_type') != 'YouTuber': 
        return jsonify({'error': 'Only YouTubers can upload videos'}), 403 
    
    title = request.form.get('title') 
    url = request.form.get('video_url') 
    user_id = session.get('user_id') 
    
    # Validate input
    if not title or not url:
        return jsonify({'error': 'Title and video URL are required'}), 400
    
    try:
        video = Video(title=title, video_url=url, added_by=user_id) 
        db.session.add(video) 
        db.session.commit() 
        
        # Log video upload
        log_user_ip(user_id, "video_upload")
        
        # For AJAX requests, return JSON
        if request.headers.get('Content-Type') == 'application/json' or request.is_json:
            return jsonify({
                'success': True,
                'message': 'Video uploaded successfully!',
                'redirect': url_for('upload_success', video_id=video.id)
            })
        
        # For form submissions, redirect to success page
        return redirect(url_for('upload_success', video_id=video.id))
        
    except Exception as e:
        print(f"❌ Video upload error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to upload video. Please try again.'}), 500

@app.route('/upload_success')
@app.route('/upload_success/<int:video_id>')
def upload_success(video_id=None):
    """Display video upload success page"""
    if session.get('account_type') != 'YouTuber': 
        return redirect(url_for('youtuber_dashboard'))
    
    # Get video details if video_id is provided
    video = None
    if video_id:
        video = Video.query.get(video_id)
        # Ensure the video belongs to the current user
        if video and video.added_by != session.get('user_id'):
            video = None
    
    # Get some stats for the page
    try:
        total_videos = Video.query.count()
        total_users = User.query.count()
        total_earned = db.session.query(db.func.sum(User.balance_usd)).scalar() or 0
    except:
        total_videos = 0
        total_users = 0
        total_earned = 0
    
    # Prepare template data
    template_data = {
        'video_title': video.title if video else None,
        'upload_time': video.timestamp.strftime('%B %d, %Y at %I:%M %p') if video else None,
        'total_videos': total_videos,
        'active_users': total_users,
        'total_earned': f"{total_earned:,.2f}"
    }
    
    return render_template('upload_success.html', **template_data)

@app.route('/logout')
def logout():
    """Logout user and clear session"""
    user_id = session.get('user_id')
    if user_id:
        # Log logout
        log_user_ip(user_id, "logout")
    
    session.clear()
    return redirect(url_for('home'))

#==== Database Initialization ====

def init_db():
    """Initialize database tables"""
    with app.app_context():
        db.create_all()
        print("✅ Database tables created successfully!")
        
        # Print IP tracking status
        if ENABLE_IP_TRACKING:
            print("🔍 IP tracking is ENABLED")
            print(f"📊 Keeping last {MAX_IP_HISTORY} IP addresses per user")
            if TRUST_PROXY_HEADERS:
                print("🌐 Proxy headers (X-Forwarded-For, X-Real-IP) are trusted")
        else:
            print("❌ IP tracking is DISABLED")

@app.route('/rules_popup')
def rules_popup():
    return render_template('rules_popup.html')  # or your actual template

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/debug-scan')
def debug_scan():
    import os, sys, traceback
    from flask import jsonify

    debug_result = {}
    try:
        # ✅ Check session data
        debug_result['🧠 Session'] = dict(session)

        # ✅ Check routes
        debug_result['🧭 Registered Routes'] = list(app.view_functions.keys())

        # ✅ Check template rendering
        templates_to_test = [
            'login.html', 'register.html',
            'user_dashboard.html', 'youtuber_dashboard.html',
            'withdraw.html', 'rules.html'
        ]
        missing_templates = []
        for t in templates_to_test:
            try:
                render_template(t)
            except Exception:
                missing_templates.append(t)
        debug_result['📄 Missing Templates'] = missing_templates

        # ✅ Check user table and record count
        try:
            user_count = db.session.query(User).count()
        except Exception:
            user_count = '❌ Could not access User table (maybe not defined or DB error?)'
        debug_result['👥 User Count'] = user_count

        # ✅ App config checks
        debug_result['⚙️ Config'] = {
            'DEBUG': app.config.get('DEBUG'),
            'ENV': app.config.get('ENV'),
            'SECRET_KEY set': bool(app.config.get('SECRET_KEY')),
            'SQLALCHEMY_DATABASE_URI': str(app.config.get('SQLALCHEMY_DATABASE_URI', 'Not Set'))[:50] + '...'
        }

        # ✅ Test fake register and login form simulation
        debug_result['🧪 Form Endpoints'] = {}
        try:
            # Simulate rendering login
            login_page = render_template('login.html')
            register_page = render_template('register.html')
            debug_result['🧪 Form Endpoints']['login.html rendered'] = '✅ OK' if login_page else '⚠️ Empty'
            debug_result['🧪 Form Endpoints']['register.html rendered'] = '✅ OK' if register_page else '⚠️ Empty'
        except Exception as e:
            debug_result['🧪 Form Endpoints']['error'] = f"❌ {str(e)}"

        # ✅ Render environment basics
        debug_result['📦 Environment'] = {
            'Python Version': sys.version,
            'Current Path': os.getcwd()
        }

        return jsonify(debug_result)

    except Exception as e:
        return f"<h2>❌ Debug Crash</h2><pre>{traceback.format_exc()}</pre>", 500

#==== Run App ====

if __name__ == '__main__':
    # Initialize database on startup
    init_db()
    app.run(debug=True)
else:
    # For production deployment (like Render)
    # Initialize database when app is imported
    init_db()
