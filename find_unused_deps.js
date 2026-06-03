const fs = require('fs');
const path = require('path');
const execSync = require('child_process').execSync;

function checkDeps(projectDir) {
  const pkg = JSON.parse(fs.readFileSync(path.join(projectDir, 'package.json')));
  const deps = Object.keys(pkg.dependencies || {});
  const devDeps = Object.keys(pkg.devDependencies || {});
  const allDeps = [...deps, ...devDeps];
  
  const files = execSync(`find ${projectDir}/src -type f -name "*.[jt]s*"`).toString().split('\n').filter(Boolean);
  
  let content = '';
  files.forEach(f => {
    content += fs.readFileSync(f, 'utf8') + '\n';
  });
  
  console.log(`\nProject: ${projectDir}`);
  const unused = allDeps.filter(dep => {
    // skip types and next/eslint configs
    if (dep.startsWith('@types/') || dep.includes('eslint') || dep === 'typescript' || dep === 'tailwindcss' || dep === '@tailwindcss/postcss' || dep === 'postcss') return false;
    if (dep === 'tsx' || dep === 'esbuild') return false; // used in scripts or backend
    
    // Check if dep is mentioned in the code
    // Simplistic check: does the string appear
    const depName = dep.split('/')[0]; // simple heuristic
    return !content.includes(dep) && !content.includes(`"${dep}"`) && !content.includes(`'${dep}'`);
  });
  
  console.log('Potentially Unused Dependencies:');
  console.log(unused.join('\n') || 'None');
}

checkDeps('frontend');
checkDeps('scanner');
