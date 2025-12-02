export function detectionType(evidence = '') {
    const s = (evidence || '').toLowerCase();
    if (/ai confidence|ai detected|bert/.test(s)) return 'bert';
    if (/ml confidence|naive bayes/.test(s)) return 'ml';
    if (/regex|pattern|duplicate|frequency/.test(s)) return 'regex';
    return 'unknown';
}
