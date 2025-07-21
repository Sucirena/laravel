import './bootstrap';
import 'flowbite';
import 'preline'

const offcanvasTrigger = document.querySelector('[data-hs-overlay="#hs-offcanvas-example"]');
        const offcanvas = document.getElementById('hs-offcanvas-example');

        // Tambahkan transisi untuk animasi smooth
        offcanvasTrigger.addEventListener('click', () => {
            const isHidden = offcanvas.classList.contains('hidden');
            if (isHidden) {
            offcanvas.classList.remove('hidden');
            setTimeout(() => {
                offcanvas.classList.remove('-translate-x-full');
            }, 10); // Delay untuk memulai transisi
            } else {
            offcanvas.classList.add('-translate-x-full');
            offcanvas.addEventListener(
                'transitionend',
                () => offcanvas.classList.add('hidden'),
                { once: true }
            );
            }
        });

        // Menutup dengan tombol close
        const closeButton = offcanvas.querySelector('[aria-label="Close"]');
        closeButton.addEventListener('click', () => {
            offcanvas.classList.add('-translate-x-full');
            offcanvas.addEventListener(
            'transitionend',
            () => offcanvas.classList.add('hidden'),
            { once: true }
            );
        });
