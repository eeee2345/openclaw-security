#!/usr/bin/env node
/**
 * Post-install welcome message for Panguard AI CLI.
 * Shows a branded banner so users know installation succeeded.
 */

const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const GREEN = '\x1b[32m';
const CYAN = '\x1b[36m';
const WHITE = '\x1b[37m';

const version = process.env.npm_package_version || '0.2.0';

const banner = `
${GREEN}${BOLD}  ____                                      _     _    _${RESET}
${GREEN}${BOLD} |  _ \\ __ _ _ __   __ _ _   _  __ _ _ __ __| |   / \\  |_|${RESET}
${GREEN}${BOLD} | |_) / _\` | '_ \\ / _\` | | | |/ _\` | '__/ _\` |  / _ \\  | |${RESET}
${GREEN}${BOLD} |  __/ (_| | | | | (_| | |_| | (_| | | | (_| | / ___ \\ | |${RESET}
${GREEN}${BOLD} |_|   \\__,_|_| |_|\\__, |\\__,_|\\__,_|_|  \\__,_|/_/   \\_\\|_|${RESET}
${GREEN}${BOLD}                    |___/${RESET}
${DIM}  AI-Powered Endpoint Security ${WHITE}v${version}${RESET}

${BOLD}  Installation complete.${RESET} Get started:

${CYAN}    panguard scan${RESET}          ${DIM}Run a security scan on this machine${RESET}
${CYAN}    panguard guard start${RESET}   ${DIM}Start real-time threat monitoring${RESET}
${CYAN}    panguard login${RESET}         ${DIM}Log in to your Panguard account${RESET}
${CYAN}    panguard --help${RESET}        ${DIM}Show all available commands${RESET}

${DIM}  Docs: https://panguard.ai/docs/getting-started${RESET}
`;

console.log(banner);
