# Simple PHP + Apache base
FROM php:8.2-apache

# Make sure only ONE MPM is enabled (prefork for PHP)
RUN a2dismod mpm_event mpm_worker || true \
 && a2enmod mpm_prefork

# Copy your app into the web root
# Make sure your repo root has index.php, verify-human.php, etc.
COPY . /var/www/html/

# Permissions
RUN chown -R www-data:www-data /var/www/html

# (Optional) .htaccess / rewrites, only if you need them
# RUN a2enmod rewrite

# Minimal hardening (no version leak) - optional
RUN sed -i 's/ServerTokens OS/ServerTokens Prod/i' /etc/apache2/conf-available/security.conf && \
    sed -i 's/ServerSignature On/ServerSignature Off/i' /etc/apache2/conf-available/security.conf && \
    a2enconf security

# Apache listens on 80 by default
EXPOSE 80

CMD ["apache2-foreground"]
