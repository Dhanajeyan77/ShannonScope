#!/bin/bash
FILE="src/App.tsx"

# Backgrounds
sed -i 's/bg-black/bg-white/g' $FILE
sed -i 's/bg-\[#0d1117\]/bg-gray-50/g' $FILE
sed -i 's/bg-\[#161b22\]/bg-white/g' $FILE
sed -i 's/bg-\[#050709\]/bg-gray-100/g' $FILE
sed -i 's/to-\[#0a0d14\]/to-gray-50/g' $FILE
sed -i 's/bg-gray-900/bg-gray-100/g' $FILE
sed -i 's/hover:bg-gray-800\/50/hover:bg-gray-200/g' $FILE
sed -i 's/hover:bg-gray-800\/30/hover:bg-gray-100/g' $FILE

# Text Colors
sed -i 's/text-white/text-gray-900/g' $FILE
sed -i 's/text-gray-200/text-gray-800/g' $FILE
sed -i 's/text-gray-300/text-gray-700/g' $FILE
sed -i 's/text-gray-400/text-gray-600/g' $FILE
sed -i 's/text-cyan-400/text-blue-600/g' $FILE
sed -i 's/text-cyan-500/text-blue-600/g' $FILE
sed -i 's/text-cyan-100/text-white/g' $FILE
sed -i 's/text-blue-200/text-white/g' $FILE
sed -i 's/text-emerald-200/text-white/g' $FILE
sed -i 's/text-red-100/text-white/g' $FILE
sed -i 's/text-orange-100/text-white/g' $FILE
sed -i 's/text-indigo-200/text-white/g' $FILE

# Borders
sed -i 's/border-gray-800/border-gray-300/g' $FILE
sed -i 's/border-gray-700/border-gray-300/g' $FILE
sed -i 's/border-cyan-800/border-blue-300/g' $FILE

# Accent Backgrounds
sed -i 's/bg-cyan-900\/20/bg-blue-100/g' $FILE
sed -i 's/bg-cyan-900\/30/bg-blue-100/g' $FILE
sed -i 's/bg-cyan-900\/50/bg-blue-600/g' $FILE
sed -i 's/hover:bg-cyan-800\/80/hover:bg-blue-700/g' $FILE
sed -i 's/border-cyan-500/border-blue-600/g' $FILE

# Fix Dropdown (This was the main user bug)
# Since bg-gray-900 is now bg-gray-100, the option tags will be light. We'll set text-gray-900.
sed -i 's/<option className="bg-gray-100 text-gray-900">/<option className="bg-white text-gray-900">/g' $FILE
# Make the select element have a white background so text is readable
sed -i 's/className="w-full bg-white border border-gray-300 text-blue-600 rounded px-4 py-3 text-sm focus:border-blue-500 focus:outline-none"/className="w-full bg-white border border-gray-300 text-gray-900 rounded px-4 py-3 text-sm focus:border-blue-500 focus:outline-none"/g' $FILE

