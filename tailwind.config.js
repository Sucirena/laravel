/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./resources/**/*.blade.php",
    "./resources/**/*.js",
    "./resources/**/*.vue",
    "./node_modules/flowbite/**/*.js",
    "node_modules/preline/dist/*.js"
  ],
  important: true,
  theme: {
    extend: {
      colors: {
        "color-1": "#063248",
        "color-2": "#4C606E",
        "color-3": "#298EA6",
        "color-4": "#9CA3AF",
        "color-5": "#C3E7FA",
        "color-6": "#E3F1F4",
        "color-7": "#EFEFED",
        "color-8": "#F8F8F7",
        "color-putih": "#FFFFFF",
      },
      backgroundImage: {
        "brain-pattern": "url('/public/images/brain-pattern.png')", // Background gambar
      },
      boxShadow: {
        'custom-1': '0 0 4px rgba(0, 0, 0, 0.25)',  // Bayangan ringan
      },
      fontFamily: {
        poppins: ['Poppins', 'sans-serif'],
      },
    },
  },
  plugins: [
    require(
      'daisyui', // Menggunakan daisyUI//
      'flowbite/plugin', // Menggunakan flowbite//
      'preline/plugin'), // Menggunakan preline//
  ],
}

