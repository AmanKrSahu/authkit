/**
 * Commitlint configuration file
 * Enforces conventional commit message format
 * @see https://commitlint.js.org/
 */
export default {
  // Extends the standard conventional commit rules
  extends: ['@commitlint/config-conventional'],

  // Custom rules configuration
  rules: {
    /**
     * TYPE RULES
     */
    // Allowed commit types (based on Angular convention with extensions)
    'type-enum': [
      2, // 2 = error level
      'always', // must always be one of these values
      [
        // Standard types
        'feat', // new feature
        'fix', // bug fix
        'docs', // documentation changes
        'style', // code style/formatting
        'refactor', // code refactoring
        'perf', // performance improvements
        'test', // test related changes
        'chore', // maintenance tasks
        'ci', // CI/CD changes
        'build', // build system changes
        'revert', // reverts a previous commit
        'hotfix', // critical production fix

        // Extended types
        'security', // security related changes
        'wip', // work in progress
        'dx', // developer experience improvements
        'analytics', // analytics tracking
        'i18n', // internationalization
        'a11y', // accessibility improvements
        'ops', // operational changes
        'merge', // merge commits
        'config', // configuration changes
        'vendor', // vendor/dependency updates
        'experiment', // experimental features
      ],
    ],

    /**
     * SCOPE RULES
     */
    // Allowed scopes (customize based on your project structure)
    'scope-enum': [
      2, // error level
      'always', // must always be one of these values
      [
        // Application structure
        'app', // main application
        'api', // API related
        'db', // database related
        'auth', // authentication

        // Frontend
        'ui', // user interface
        'ux', // user experience
        'layout', // layout changes
        'component', // component changes
        'hook', // react hooks

        // Shared
        'util', // utilities
        'middleware', // middleware
        'validation', // validation logic
        'error', // error handling
        'logging', // logging

        // Configuration
        'config', // configuration files
        'deps', // dependencies
        'types', // type definitions

        // Testing
        'tests', // general tests
        'e2e', // end-to-end tests
        'unit', // unit tests
        'integration', // integration tests

        // DevOps
        'ci', // continuous integration
        'cd', // continuous deployment
        'docker', // docker configuration
        'nginx', // web server config

        // Business domains
        'security', // security features
        'checkout', // checkout process
        'cart', // shopping cart
        'search', // search functionality
        'profile', // user profiles
        'payment', // payment processing
        'notification', // notifications
        'email', // email related
        'reporting', // reporting features
        'admin', // admin features
      ],
    ],

    /**
     * FORMATTING RULES
     */
    // Subject must be lowercase
    'subject-case': [2, 'always', 'lower-case'],
    // Header (first line) max length (GitHub recommendation)
    'header-max-length': [2, 'always', 72],
    // Footer lines max length
    'footer-max-line-length': [2, 'always', 100],
    // Body lines max length
    'body-max-line-length': [2, 'always', 100],

    /**
     * REQUIRED/EMPTY CHECKS
     */
    // Type cannot be empty
    'type-empty': [2, 'never'],
    // Scope should not be empty (warning level 1 rather than error)
    'scope-empty': [1, 'never'],
    // Subject cannot be empty
    'subject-empty': [2, 'never'],
    // Subject cannot end with a dot
    'subject-full-stop': [2, 'never', '.'],

    /**
     * SPACING RULES
     */
    // Body must have leading blank line
    'body-leading-blank': [2, 'always'],
    // Footer must have leading blank line
    'footer-leading-blank': [2, 'always'],
  },
};
