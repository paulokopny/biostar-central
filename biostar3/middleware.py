from __future__ import absolute_import, division, print_function, unicode_literals
import hmac
import logging

from django.contrib import messages
from django.conf import settings
from django.contrib.auth import get_user_model, login
from django.http import HttpResponsePermanentRedirect as Redirect
from django.contrib.sites.models import Site
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from biostar3.forum import cache, models, auth


# Get current site
User = get_user_model()

logger = logging.getLogger("biostar")

class AutoSignupAdapter(DefaultSocialAccountAdapter):
    def pre_social_login(self, request, sociallogin):

        # This social login already exists.
        if sociallogin.is_existing:
            return

        try:

            # The provider that produces the login
            provider_id = sociallogin.account.get_provider().id

            # Check if we could/should connect it.
            email = sociallogin.account.extra_data.get('email')

            logger.info("connecting %s with %s" % (email, provider_id))

            # Try to get the verification for the account
            verified = sociallogin.account.extra_data.get('verified_email')

            # We will trust some social account providers with the email information.
            verified = verified or (provider_id in settings.TRUSTED_SOCIALACCOUNT_PROVIDERS)

            if email:
                user = User.objects.get(email=email)
                if verified:
                    sociallogin.connect(request, user)
                else:
                    msg = "Attempt to log with email from non verified provider!"
                    logger.error(msg)
                    raise Exception(msg)

        except User.DoesNotExist:
            pass

DOMAIN_CACHE = dict()



class ExternalAuth(object):
    '''
    This is an "autentication" that relies on the user being valid.
    We're just following the Django interfaces here.
    '''

    def authenticate(self, email, valid=False):
        # Check the username/password and return a User.
        if valid:
            user = User.objects.get(email=email)
            user.backend = "%s.%s" % (__name__, self.__class__.__name__)
            # print user.backend
            return user
        else:
            return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

def valid_external_login(request):
    "Attempts to perform an external login"

    for name, key in settings.EXTERNAL_AUTH:
        value = request.COOKIES.get(name)
        if value:
            try:
                email, digest1 = value.split(":")
                digest2 = hmac.new(key, email).hexdigest()
                valid = (digest1 == digest2)
                if not valid:
                    raise Exception("digests do not match")
            except Exception, exc:
                logger.error(exc)
                return False

            # If we made it this far the data is valid.
            user, flag = User.objects.get_or_create(email=email)
            if flag:
                logger.info("created user %s" % user.email)

            # Authenticate with local info.
            user = ExternalAuth().authenticate(email=user.email, valid=valid)
            login(request=request, user=user)
            return True

    return False


class GlobalMiddleware(object):
    """Performs tasks that are applied on every request"""

    def process_request(self, request):
        global DOMAIN_CACHE
        user = request.user

        # Ensures that request data have all the information needed.
        auth.add_user_attributes(user)

        # Find the domain
        domain = settings.GET_DOMAIN(request)
        site = DOMAIN_CACHE.get(domain)

        # The site not found in the domain cache.
        if not site:

            # Try to find the site among the existin ones.
            site = Site.objects.filter(domain=domain).first()

            if not site:
                request.site = None
                from biostar3.forum.post_views import invalid_site
                return invalid_site(request, domain)

            # Existing site goes into the cache.
            DOMAIN_CACHE[domain] = site

        if not user.is_authenticated():

            # Check external logins.
            if settings.EXTERNAL_AUTH and valid_external_login(request):
                messages.success(request, "Login completed")

        # Add the subscription information to each request.
        subs = []
        if user.is_authenticated():
            subs = request.session.get(settings.SUBSCRIPTION_CACHE_NAME)

            # Set the subscriptions into the session.
            if not subs:
                subs = [s.site.id for s in models.SiteSub.objects.filter(user=user)]
                request.session[settings.SUBSCRIPTION_CACHE_NAME] = subs

        request.site = site
        request.subs = subs