FROM php:8.2-apache

# Make sure only ONE MPM is enabled (fixes AH00534)
RUN a2dismod mpm_event mpm_worker || true \
 && a2enmod mpm_prefork

# Put our app in the Apache web root
WORKDIR /var/www/html
COPY . /var/www/html/

# Permissions
RUN chown -R www-data:www-data /var/www/html

# Optional: enable rewrite later if you need .htaccess
# RUN a2enmod rewrite

EXPOSE 80

CMD ["apache2-foreground"]
