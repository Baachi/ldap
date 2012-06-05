<?php
namespace TYPO3\LDAP\Service;

/*                                                                        *
 * This script belongs to the FLOW3 package "TYPO3.LDAP".                 *
 *                                                                        *
 * It is free software; you can redistribute it and/or modify it under    *
 * the terms of the GNU Lesser General Public License as published by the *
 * Free Software Foundation, either version 3 of the License, or (at your *
 * option) any later version.                                             *
 *                                                                        *
 * This script is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHAN-    *
 * TABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser       *
 * General Public License for more details.                               *
 *                                                                        *
 * You should have received a copy of the GNU Lesser General Public       *
 * License along with the script.                                         *
 * If not, see http://www.gnu.org/licenses/lgpl.html                      *
 *                                                                        *
 * The TYPO3 project - inspiring people to share!                         *
 *                                                                        */

use TYPO3\FLOW3\Annotations as FLOW3;

/**
 * A simple LDAP authentication service
 * @FLOW3\Scope("prototype")
 */
class DirectoryService {

	/**
	 * @var string
	 */
	protected $name;

	/**
	 * @var array
	 */
	protected $options;

	/**
	 * @var \TYPO3\LDAP\Service\BindProvider\BindProviderInterface
	 */
	protected $bindProvider;

	/**
	 * @param $name
	 * @param array $options
	 * @return void
	 */
	public function __construct($name, array $options) {
		$this->name = $name;
		$this->options = $options;

		if (!extension_loaded('ldap')) {
			throw new \TYPO3\FLOW3\Error\Exception('PHP is not compiled with LDAP support', 1305406047);
		}
	}

	/**
	 * Initialize the LDAP server connection
	 *
	 * Connect to the server and set communication options. Further bindings will be done
	 * by a server specific bind provider.
	 *
	 * @throws \TYPO3\FLOW3\Error\Exception
	 */
	public function ldapConnect() {
		$bindProviderClassName = 'TYPO3\LDAP\Service\BindProvider\\' . $this->options['type'] . 'Bind';
		if (!class_exists($bindProviderClassName)) {
			throw new \TYPO3\FLOW3\Error\Exception('An bind provider for the service "' . $this->options['type'] . '" could not be resolved. Make sure it is a valid bind provider name!', 1327756744);
		}

		try {
			$connection = ldap_connect($this->options['host'], $this->options['port']);
			$this->bindProvider = new $bindProviderClassName($connection, $this->options);
			$this->setLdapOptions();
		} catch (\Exception $exception) {
			throw new \TYPO3\FLOW3\Error\Exception('Could not connect to LDAP server', 1326985286);
		}
	}

	/**
	 * Set the LDAP options configured in the settings
	 *
	 * Loops over the ldapOptions array, and finds the corresponding LDAP option by prefixing
	 * LDAP_OPT_ to the uppercased array key.
	 *
	 * Example:
	 *  protocol_version: 3
	 * Becomes:
	 *  LDAP_OPT_PROTOCOL_VERSION 3
	 *
	 * @return void
	 */
	protected function setLdapOptions() {
		if (!empty($this->options['ldapOptions']) && is_array($this->options['ldapOptions'])) {
			foreach ($this->options['ldapOptions'] as $ldapOption => $ldapOptionValue) {
				$constantName = 'LDAP_OPT_' . strtoupper($ldapOption);
				ldap_set_option($this->bindProvider->getLinkIdentifier(), constant($constantName), $ldapOptionValue);
			}
		}
	}

	/**
	 * Authenticate a username / password against the LDAP server
	 *
	 * @param string $username
	 * @param string $password
	 * @return array Search result from LDAP
	 * @throws \TYPO3\FLOW3\Error\Exception
	 */
	public function authenticate($username, $password) {
		try {
			$this->ldapConnect();
			$this->bindProvider->bind($username, $password);
			$entries = $this->getUserEntries($username);
			if (!empty($entries)) {
				$this->bindProvider->verifyCredentials($entries[0]['dn'], $password);
				// get all entries in the second run in the case of anonymous bind
				// TODO: avoid unnecessary search requests
				$entries = $this->getUserEntries($username);
			}
			return $entries[0];
		} catch (\Exception $exception) {
			throw new \TYPO3\FLOW3\Error\Exception('Error during LDAP server authentication: ' . $exception->getMessage(), 1323167213);
		}
	}

	/**
	 * Get the user entities from the LDAP server
	 * At least the dn should be returned.
	 *
	 * @param $username
	 * @return array
	 */
	public function getUserEntries($username) {
		$searchResult = ldap_search(
			$this->bindProvider->getLinkIdentifier(),
			$this->options['baseDn'],
			str_replace(
				'?',
				$this->bindProvider->getFilteredUsername($username),
				$this->options['filter']['account']
			)
		);
		if ($searchResult) {
			$entries = ldap_get_entries($this->bindProvider->getLinkIdentifier(), $searchResult);

			if ($entries['count'] === 1) {
				return $entries;
			}
		}
	}

	/**
	 * Check if the server is online / can be reached
	 * TODO: make a fancy version of this method
	 *
	 * @return boolean
	 */
	public function isServerOnline() {
		return \TYPO3\LDAP\Utility\ServerStatusUtility::isServerOnline($this->options['host'], $this->options['port']);
	}

}

?>