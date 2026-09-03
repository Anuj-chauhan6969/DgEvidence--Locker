// Image Carousel Functionality
let currentImage = 0;
const carouselImages = document.querySelectorAll('.carousel-image');
const leftArrow = document.querySelector('.arrow-btn.left');
const rightArrow = document.querySelector('.arrow-btn.right');
const heroSection = document.querySelector('.hero-section');
let autoRotateInterval;



function showImage(index, direction = 'auto') {
    const currentActive = document.querySelector('.carousel-image.active');
    const nextActive = carouselImages[index];

    // Pause current video if exists
    if (currentActive && currentActive.tagName === 'VIDEO') {
        currentActive.pause();
    }

    // Remove active class
    carouselImages.forEach(img => img.classList.remove('active'));

    // Position all images for continuous reel effect
    carouselImages.forEach((img, i) => {
        if (direction === 'prev') {
            // Left arrow: slide left-to-right
            if (i < index) {
                img.style.transform = 'translateX(-100%)';
            } else if (i > index) {
                img.style.transform = 'translateX(100%)';
            } else {
                img.style.transform = 'translateX(0%)';
            }
        } else {
            // Auto-rotation and right arrow: slide right-to-left
            if (i < index) {
                img.style.transform = 'translateX(100%)';
            } else if (i > index) {
                img.style.transform = 'translateX(-100%)';
            } else {
                img.style.transform = 'translateX(0%)';
            }
        }

        img.style.opacity = '1';
        img.style.transition = 'transform 0.4s ease-in-out';
    });

    // Make new image active and play video
    nextActive.classList.add('active');
    if (nextActive.tagName === 'VIDEO') {
        nextActive.play();
    }
}

function nextImage() {
    currentImage = (currentImage + 1) % carouselImages.length;
    showImage(currentImage, 'next');
}

function prevImage() {
    currentImage = (currentImage - 1 + carouselImages.length) % carouselImages.length;
    showImage(currentImage, 'prev');
}

function startAutoRotate() {
    autoRotateInterval = setInterval(nextImage, 3800);
}

function stopAutoRotate() {
    clearInterval(autoRotateInterval);
}

// Event listeners
leftArrow.addEventListener('click', prevImage);
rightArrow.addEventListener('click', nextImage);

// Pause on hover - hero section
heroSection.addEventListener('mouseenter', () => {
    stopAutoRotate();
    console.log('Mouse entered hero section - auto-rotation stopped');
});

heroSection.addEventListener('mouseleave', () => {
    startAutoRotate();
    console.log('Mouse left hero section - auto-rotation started');
});

// Start auto-rotation
startAutoRotate();
