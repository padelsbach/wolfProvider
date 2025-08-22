/*
 * Copyright (C) 2006-2024 wolfSSL Inc.
 *
 * This file is part of wolfProvider.
 *
 * wolfProvider is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfProvider is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wolfProvider. If not, see <http://www.gnu.org/licenses/>.
 */

/* Note: to simplify the build process, we are not using the OpenSSL headers.
 *       Instead, we are using functions that don't specify parameters. This
 *       allows us to build the stub without having to clone OpenSSL first,
 *       nor use the system OpenSSL headers.
 */

/* Prototype of public function that initializes the wolfSSL provider. */
int wolfssl_provider_init();

/* Prototype for the wolfprov_provider_init function */
int wolfprov_provider_init();

/*
 * Provider implementation stub
 */
int wolfprov_provider_init()
{
    return 0;
}
