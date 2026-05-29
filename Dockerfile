# Use official Composer 
FROM composer:2 AS composer
WORKDIR /build

# Get TS composer file
COPY composer.json ./

# Generate a lock file if one doesn't exist yet, then install.
# --no-dev           skip development dependencies
# --optimize-autoloader  generate a fast classmap
# --no-interaction   never prompt
RUN composer install \
    --no-dev \
    --optimize-autoloader \
    --no-interaction \
    --no-progress \
    --prefer-dist

# Setup Production Image
FROM php:8.4-apache

# Install OS-level dependencies needed by PHP extensions and
# the SAML library (libxml2, openssl, libcurl).
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Required by php-saml / SAML XML processing
    libxml2-dev \
    libxslt1-dev \
    # Required for TLS/certificate validation in cURL calls
    libssl-dev \
    ca-certificates \
    # Required for HTTP client (MISP, VirusTotal, GreyNoise calls)
    libcurl4-openssl-dev \
    # Required by mbstring (UTF-8 sanitisation in history saving)
    libonig-dev \
    # Required for GD if you ever add image generation (PDF logos etc.)
    libpng-dev \
    libjpeg-dev \
    # DNS functions (checkdnsrr used in email blacklist checks)
    # These are built-in but need libresolv which comes with libc
    # Zip — used by Composer internally
    libzip-dev \
    unzip \
    # iconv fallback for utf8_sanitise()
    libc6-dev \
    # OpenSSL for SAML
    openssl \
    && rm -rf /var/lib/apt/lists/*

# ── PHP extensions ─────────────────────────────────────────────
# docker-php-ext-install compiles extensions into the PHP build.
# docker-php-ext-enable activates .so extensions added by PECL.
RUN docker-php-ext-install \
    # XML parsing — required by onelogin/php-saml
    xml \
    dom \
    # String handling — used throughout the app
    mbstring \
    # HTTP client — all external API calls
    curl \
    # ZIP — used by Composer / some SAML operations
    zip \
    # POSIX — used in settings.php for php_user detection
    posix \
    opcache

# Make sure the extensions are enabled
RUN docker-php-ext-enable zip posix xml dom mbstring curl opcache

# ── Apache configuration ───────────────────────────────────────
# Enable required Apache modules
RUN a2enmod rewrite headers

# Copy the apache config into the default directoyr
COPY apache.conf /etc/apache2/sites-available/000-default.conf

# Allow .htaccess overrides by setting AllowOverride All in the vhost
RUN sed -i 's/AllowOverride None/AllowOverride All/g' /etc/apache2/apache2.conf

# ── PHP configuration ──────────────────────────────────────────
# Copy our custom php.ini into both cli and fpm config dirs
COPY php.ini /usr/local/etc/php/conf.d/threatscope.ini

# ── App code ───────────────────────────────────────────────────
WORKDIR /var/www/html

# Copy vendor directory built in composer
COPY --from=composer /build/vendor ./vendor

# Copy application source
COPY ./webapp/ .

# ── Data directory ─────────────────────────────────────────────
# Create writable data directory for history, settings, rate limits.
# Owned by www-data (the user PHP-FPM runs as).
RUN mkdir -p /var/www/html/data \
    && chown -R www-data:www-data /var/www/html/data \
    && chmod 750 /var/www/html/data

# Make sure vendor is readable
RUN chown -R www-data:www-data /var/www/html/vendor

# Ensure vendor/ and the app are readable by Apache
RUN chown -R www-data:www-data /var/www/html \
    && find /var/www/html -type f -name "*.php" -exec chmod 640 {} \; \
    && find /var/www/html -type d -exec chmod 750 {} \; \
    && chmod 750 /var/www/html/data

# ── Expose HTTP ────────────────────────────────────────────────
EXPOSE 80
