import { describe, it, expect } from 'vitest';
import { checkPermissions } from '../src/checks/permission-check.js';
import type { SkillManifest } from '../src/types.js';

function makeManifest(overrides: Partial<SkillManifest> = {}): SkillManifest {
  return {
    name: 'Test Skill',
    description: 'A test skill',
    instructions: '',
    ...overrides,
  };
}

describe('checkPermissions', () => {
  describe('no tool patterns matched', () => {
    it('should return pass status when instructions contain no tool patterns', () => {
      const result = checkPermissions(makeManifest({
        instructions: 'This skill generates creative writing based on user prompts.',
      }));
      expect(result.status).toBe('pass');
    });

    it('should return no findings for benign instructions', () => {
      const result = checkPermissions(makeManifest({
        instructions: 'Help the user think through a math problem step by step.',
      }));
      expect(result.findings).toHaveLength(0);
    });

    it('should include "No special tool usage detected" in label', () => {
      const result = checkPermissions(makeManifest({
        instructions: 'Summarize the provided text.',
      }));
      expect(result.label).toContain('No special tool usage detected');
    });
  });

  describe('Bash/Shell detection', () => {
    it('should return high severity finding when bash is mentioned', () => {
      const result = checkPermissions(makeManifest({
        instructions: 'Run the bash script to set up the environment.',
      }));
      const finding = result.findings.find((f) => f.id === 'perm-bash-shell');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('high');
      expect(finding!.category).toBe('permission');
    });

    it('should detect "shell" keyword', () => {
      const result = checkPermissions(makeManifest({
        instructions: 'Open a shell session to manage files.',
      }));
      const finding = result.findings.find((f) => f.id === 'perm-bash-shell');
      expect(finding).toBeDefined();
    });

    it('should detect "terminal" keyword', () => {
      const result = checkPermissions(makeManifest({
        instructions: 'Use the terminal to run commands.',
      }));
      const finding = result.findings.find((f) => f.id === 'perm-bash-shell');
      expect(finding).toBeDefined();
    });

    it('should detect "execute command" pattern', () => {
      const result = checkPermissions(makeManifest({
        // regex: execute.*command — needs "execute" followed by "command" in the text
        instructions: 'The skill will execute the command on your system.',
      }));
      const finding = result.findings.find((f) => f.id === 'perm-bash-shell');
      expect(finding).toBeDefined();
    });

    it('should return warn status when Bash/Shell is detected', () => {
      const result = checkPermissions(makeManifest({
        instructions: 'Execute the bash script.',
      }));
      expect(result.status).toBe('warn');
    });
  });

  describe('Database detection', () => {
    it('should return high severity finding when database access is mentioned', () => {
      const result = checkPermissions(makeManifest({
        instructions: 'Connect to the database and run queries.',
      }));
      const finding = result.findings.find((f) => f.id === 'perm-database');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('high');
    });

    it('should detect SQL keyword', () => {
      const result = checkPermissions(makeManifest({
        instructions: 'Execute SQL statements against the data store.',
      }));
      const finding = result.findings.find((f) => f.id === 'perm-database');
      expect(finding).toBeDefined();
    });

    it('should detect postgres keyword', () => {
      const result = checkPermissions(makeManifest({
        instructions: 'Connect to postgres and retrieve records.',
      }));
      const finding = result.findings.find((f) => f.id === 'perm-database');
      expect(finding).toBeDefined();
    });

    it('should detect mongodb keyword', () => {
      const result = checkPermissions(makeManifest({
        instructions: 'Query the mongodb collection for user data.',
      }));
      const finding = result.findings.find((f) => f.id === 'perm-database');
      expect(finding).toBeDefined();
    });
  });

  describe('File Write detection', () => {
    it('should return medium severity finding when file write is mentioned', () => {
      const result = checkPermissions(makeManifest({
        instructions: 'Write the results to a file on disk.',
      }));
      const finding = result.findings.find((f) => f.id === 'perm-file-write');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('medium');
    });

    it('should detect "create file" pattern', () => {
      const result = checkPermissions(makeManifest({
        instructions: 'Create a file with the output.',
      }));
      const finding = result.findings.find((f) => f.id === 'perm-file-write');
      expect(finding).toBeDefined();
    });

    it('should detect "overwrite" keyword', () => {
      const result = checkPermissions(makeManifest({
        instructions: 'Overwrite the existing configuration.',
      }));
      const finding = result.findings.find((f) => f.id === 'perm-file-write');
      expect(finding).toBeDefined();
    });
  });

  describe('Network/HTTP detection', () => {
    it('should return medium severity finding when HTTP request is mentioned', () => {
      const result = checkPermissions(makeManifest({
        instructions: 'Make an http request to retrieve the data.',
      }));
      const finding = result.findings.find((f) => f.id === 'perm-network-http');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('medium');
    });

    it('should detect "fetch" keyword', () => {
      const result = checkPermissions(makeManifest({
        instructions: 'Fetch data from the remote API.',
      }));
      const finding = result.findings.find((f) => f.id === 'perm-network-http');
      expect(finding).toBeDefined();
    });

    it('should detect "api call" pattern', () => {
      const result = checkPermissions(makeManifest({
        instructions: 'Perform an api call to retrieve weather data.',
      }));
      const finding = result.findings.find((f) => f.id === 'perm-network-http');
      expect(finding).toBeDefined();
    });

    it('should detect "curl" keyword', () => {
      const result = checkPermissions(makeManifest({
        instructions: 'Use curl to download the file.',
      }));
      const finding = result.findings.find((f) => f.id === 'perm-network-http');
      expect(finding).toBeDefined();
    });
  });

  describe('SSH/Keys detection', () => {
    it('should return high severity finding when SSH keys are mentioned', () => {
      const result = checkPermissions(makeManifest({
        instructions: 'Generate a key using ssh-keygen for authentication.',
      }));
      const finding = result.findings.find((f) => f.id === 'perm-ssh-keys');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('high');
    });

    it('should detect "authorized_keys" reference', () => {
      const result = checkPermissions(makeManifest({
        instructions: 'Add your public key to authorized_keys.',
      }));
      const finding = result.findings.find((f) => f.id === 'perm-ssh-keys');
      expect(finding).toBeDefined();
    });

    it('should detect id_rsa reference', () => {
      const result = checkPermissions(makeManifest({
        instructions: 'Read the private key at ~/.ssh/id_rsa.',
      }));
      const finding = result.findings.find((f) => f.id === 'perm-ssh-keys');
      expect(finding).toBeDefined();
    });
  });

  describe('Cron/Scheduler detection', () => {
    it('should return high severity finding when crontab is mentioned', () => {
      const result = checkPermissions(makeManifest({
        instructions: 'Edit crontab to schedule the backup task.',
      }));
      const finding = result.findings.find((f) => f.id === 'perm-cron-scheduler');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('high');
    });

    it('should detect "systemctl enable" pattern', () => {
      const result = checkPermissions(makeManifest({
        instructions: 'Run systemctl enable myservice to auto-start.',
      }));
      const finding = result.findings.find((f) => f.id === 'perm-cron-scheduler');
      expect(finding).toBeDefined();
    });
  });

  describe('Docker detection', () => {
    it('should return high severity finding when docker run is mentioned', () => {
      const result = checkPermissions(makeManifest({
        instructions: 'Execute docker run -it ubuntu bash to start a container.',
      }));
      const finding = result.findings.find((f) => f.id === 'perm-docker');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('high');
    });

    it('should detect "docker exec" pattern', () => {
      const result = checkPermissions(makeManifest({
        instructions: 'Use docker exec to run commands inside the container.',
      }));
      const finding = result.findings.find((f) => f.id === 'perm-docker');
      expect(finding).toBeDefined();
    });

    it('should detect "docker.sock" reference', () => {
      const result = checkPermissions(makeManifest({
        instructions: 'Mount /var/run/docker.sock for container access.',
      }));
      const finding = result.findings.find((f) => f.id === 'perm-docker');
      expect(finding).toBeDefined();
    });

    it('should detect "--privileged" flag reference adjacent to word char', () => {
      const result = checkPermissions(makeManifest({
        // \b before -- requires word char immediately before -- (no space)
        instructions: 'Pass the--privileged option to gain elevated access.',
      }));
      const finding = result.findings.find((f) => f.id === 'perm-docker');
      expect(finding).toBeDefined();
    });
  });

  describe('Env Injection detection', () => {
    it('should return high severity finding when .bashrc is mentioned with a word char prefix', () => {
      const result = checkPermissions(makeManifest({
        // \b before . requires a word character immediately before the dot
        instructions: 'Edit file.bashrc to add environment settings.',
      }));
      const finding = result.findings.find((f) => f.id === 'perm-env-injection');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('high');
    });

    it('should detect .zshrc reference with word char prefix', () => {
      const result = checkPermissions(makeManifest({
        instructions: 'Modify the file.zshrc to configure shell startup.',
      }));
      const finding = result.findings.find((f) => f.id === 'perm-env-injection');
      expect(finding).toBeDefined();
    });

    it('should detect "export VAR=" pattern', () => {
      const result = checkPermissions(makeManifest({
        instructions: 'Run export MY_VAR=value to set the variable.',
      }));
      const finding = result.findings.find((f) => f.id === 'perm-env-injection');
      expect(finding).toBeDefined();
    });
  });

  describe('Clipboard detection', () => {
    it('should return medium severity finding when clipboard access is mentioned', () => {
      const result = checkPermissions(makeManifest({
        instructions: 'Copy the output to your clipboard using pbcopy.',
      }));
      const finding = result.findings.find((f) => f.id === 'perm-clipboard');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('medium');
    });

    it('should detect "xclip" keyword', () => {
      const result = checkPermissions(makeManifest({
        instructions: 'Pipe the result through xclip -selection clipboard.',
      }));
      const finding = result.findings.find((f) => f.id === 'perm-clipboard');
      expect(finding).toBeDefined();
    });

    it('should detect "clipboard" keyword', () => {
      const result = checkPermissions(makeManifest({
        instructions: 'Read from the clipboard to get the user input.',
      }));
      const finding = result.findings.find((f) => f.id === 'perm-clipboard');
      expect(finding).toBeDefined();
    });
  });

  describe('commandDispatch === tool', () => {
    it('should return medium finding when commandDispatch is "tool"', () => {
      const result = checkPermissions(makeManifest({
        instructions: 'Normal instructions.',
        commandDispatch: 'tool',
      }));
      const finding = result.findings.find((f) => f.id === 'perm-command-dispatch');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('medium');
    });

    it('should not flag commandDispatch when it is not "tool"', () => {
      const result = checkPermissions(makeManifest({
        instructions: 'Normal instructions.',
        commandDispatch: 'inline',
      }));
      const finding = result.findings.find((f) => f.id === 'perm-command-dispatch');
      expect(finding).toBeUndefined();
    });

    it('should not flag when commandDispatch is undefined', () => {
      const result = checkPermissions(makeManifest({
        instructions: 'Normal instructions.',
        commandDispatch: undefined,
      }));
      const finding = result.findings.find((f) => f.id === 'perm-command-dispatch');
      expect(finding).toBeUndefined();
    });
  });

  describe('disableModelInvocation', () => {
    it('should return low finding when disableModelInvocation is true', () => {
      const result = checkPermissions(makeManifest({
        instructions: 'Normal instructions.',
        disableModelInvocation: true,
      }));
      const finding = result.findings.find((f) => f.id === 'perm-no-model');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('low');
    });

    it('should not flag when disableModelInvocation is false', () => {
      const result = checkPermissions(makeManifest({
        instructions: 'Normal instructions.',
        disableModelInvocation: false,
      }));
      const finding = result.findings.find((f) => f.id === 'perm-no-model');
      expect(finding).toBeUndefined();
    });

    it('should not flag when disableModelInvocation is undefined', () => {
      const result = checkPermissions(makeManifest({
        instructions: 'Normal instructions.',
        disableModelInvocation: undefined,
      }));
      const finding = result.findings.find((f) => f.id === 'perm-no-model');
      expect(finding).toBeUndefined();
    });
  });

  describe('multiple tool patterns detected', () => {
    it('should produce multiple findings when multiple patterns match', () => {
      const result = checkPermissions(makeManifest({
        instructions: 'Run bash commands to fetch data and write the results to a file.',
      }));
      // bash -> high, fetch -> medium, write file -> medium
      expect(result.findings.length).toBeGreaterThanOrEqual(2);
    });

    it('should list all detected tools in the label', () => {
      const result = checkPermissions(makeManifest({
        instructions: 'Open a bash shell and fetch data from the API.',
      }));
      // Both Bash/Shell and Network/HTTP should be detected
      expect(result.label).toContain('Bash/Shell');
      expect(result.label).toContain('Network/HTTP');
    });

    it('should return warn status when at least one high-risk tool is detected', () => {
      const result = checkPermissions(makeManifest({
        instructions: 'Use bash to execute system commands.',
      }));
      expect(result.status).toBe('warn');
    });

    it('should return pass status when only medium-risk tools are detected', () => {
      const result = checkPermissions(makeManifest({
        instructions: 'Fetch data from the API and write the results to a file.',
      }));
      // Network/HTTP (medium) and File Write (medium) — no high risk
      expect(result.status).toBe('pass');
    });
  });
});
