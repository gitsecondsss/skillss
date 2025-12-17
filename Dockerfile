FROM php:8.2-apache

# Optional: remove Apache FQDN warning
RUN echo "ServerName localhost" > /etc/apache2/conf-available/servername.conf \
 && a2enconf servername

# Copy application files
COPY . /var/www/html

# Permissions
RUN chown -R www-data:www-data /var/www/html

# Enable rewrite (safe)
RUN a2enmod rewrite

# Railway-safe start:
# - Force only prefork MPM
# - Bind Apache to Railway's $PORT
CMD ["bash", "-lc", "\
  rm -f /etc/apache2/mods-enabled/mpm_*.load /etc/apache2/mods-enabled/mpm_*.conf; \
  ln -sf /etc/apache2/mods-available/mpm_prefork.load /etc/apache2/mods-enabled/mpm_prefork.load; \
  if [ -f /etc/apache2/mods-available/mpm_prefork.conf ]; then \
    ln -sf /etc/apache2/mods-available/mpm_prefork.conf /etc/apache2/mods-enabled/mpm_prefork.conf; \
  fi; \
  : \"${PORT:=80}\"; \
  sed -i \"s/Listen 80/Listen ${PORT}/\" /etc/apache2/ports.conf; \
  sed -i \"s/<VirtualHost \\*:80>/<VirtualHost \\*:${PORT}>/\" /etc/apache2/sites-available/000-default.conf; \
  exec apache2-foreground \
"]
