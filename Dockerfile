FROM php:8.2-apache

# Make sure only ONE MPM is enabled
RUN a2dismod mpm_event mpm_worker || true \
 && a2enmod mpm_prefork

# Copy code into web root
COPY . /var/www/html/

# Permissions
RUN chown -R www-data:www-data /var/www/html

# Optional: enable rewrite if you ever need .htaccess
# RUN a2enmod rewrite

EXPOSE 80

CMD ["apache2-foreground"]
