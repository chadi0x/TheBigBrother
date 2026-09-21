/* ============================================================
   BIG BROTHER V7.0 — THREE.JS AMBIENT WEBGL BACKDROP
   Ultra-low CPU canvas rendering an interactive dot-matrix
   rotating cyber-globe and reactive particle starfield.
   ============================================================ */

(function() {
    let scene, camera, renderer, globe, particles, ring;
    let mouseX = 0, mouseY = 0;
    let targetPulse = 0;
    let isInitialized = false;

    function initThreeBackdrop() {
        const canvas = document.getElementById('three-canvas');
        if (!canvas || typeof THREE === 'undefined') return;
        if (isInitialized) return;

        try {
            scene = new THREE.Scene();
            camera = new THREE.PerspectiveCamera(55, window.innerWidth / window.innerHeight, 0.1, 1000);
            camera.position.z = 260;

            renderer = new THREE.WebGLRenderer({
                canvas: canvas,
                alpha: true,
                antialias: true,
                powerPreference: 'low-power'
            });
            renderer.setSize(window.innerWidth, window.innerHeight);
            renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

            // Dot-matrix / Wireframe Globe
            const globeGeo = new THREE.IcosahedronGeometry(88, 3);
            const globeMat = new THREE.MeshBasicMaterial({
                color: 0x00F0FF,
                wireframe: true,
                transparent: true,
                opacity: 0.14
            });
            globe = new THREE.Mesh(globeGeo, globeMat);
            scene.add(globe);

            // Outer Orbital Ring
            const ringGeo = new THREE.TorusGeometry(135, 0.6, 8, 90);
            const ringMat = new THREE.MeshBasicMaterial({
                color: 0x9D00FF,
                transparent: true,
                opacity: 0.22
            });
            ring = new THREE.Mesh(ringGeo, ringMat);
            ring.rotation.x = Math.PI / 3;
            ring.rotation.y = Math.PI / 6;
            scene.add(ring);

            // Ambient Cyber Particles
            const particleCount = 200;
            const particleGeo = new THREE.BufferGeometry();
            const coords = new Float32Array(particleCount * 3);
            for (let i = 0; i < particleCount * 3; i += 3) {
                coords[i] = (Math.random() - 0.5) * 800;
                coords[i + 1] = (Math.random() - 0.5) * 600;
                coords[i + 2] = (Math.random() - 0.5) * 600;
            }
            particleGeo.setAttribute('position', new THREE.BufferAttribute(coords, 3));
            const particleMat = new THREE.PointsMaterial({
                size: 2.0,
                color: 0x00FF9D,
                transparent: true,
                opacity: 0.38
            });
            particles = new THREE.Points(particleGeo, particleMat);
            scene.add(particles);

            window.addEventListener('mousemove', onMouseMove, { passive: true });
            window.addEventListener('resize', onWindowResize, { passive: true });

            isInitialized = true;
            animate();
        } catch (err) {
            console.warn('WebGL Backdrop initialization skipped:', err);
        }
    }

    function onMouseMove(e) {
        mouseX = (e.clientX - window.innerWidth / 2) * 0.00035;
        mouseY = (e.clientY - window.innerHeight / 2) * 0.00035;
    }

    function onWindowResize() {
        if (!camera || !renderer) return;
        camera.aspect = window.innerWidth / window.innerHeight;
        camera.updateProjectionMatrix();
        renderer.setSize(window.innerWidth, window.innerHeight);
    }

    function animate() {
        requestAnimationFrame(animate);
        if (!globe || !renderer || !scene || !camera) return;

        globe.rotation.y += 0.0018 + mouseX * 0.04;
        globe.rotation.x += 0.0009 + mouseY * 0.04;
        ring.rotation.z += 0.0022;
        ring.rotation.y -= 0.0008;
        particles.rotation.y -= 0.0004;

        if (targetPulse > 0) {
            targetPulse -= 0.02;
            const s = 1 + targetPulse * 0.08;
            globe.scale.set(s, s, s);
            globe.material.opacity = 0.14 + targetPulse * 0.25;
            globe.material.color.setHex(targetPulse > 0.4 ? 0x00FF9D : 0x00F0FF);
        } else {
            globe.scale.set(1, 1, 1);
            globe.material.opacity = 0.14;
            globe.material.color.setHex(0x00F0FF);
        }

        renderer.render(scene, camera);
    }

    window.triggerThreePulse = function() {
        targetPulse = 1.0;
        if (window.tacticalAudio) {
            window.tacticalAudio.playScanPulse();
        }
    };

    window.initThreeBackdrop = initThreeBackdrop;
})();
