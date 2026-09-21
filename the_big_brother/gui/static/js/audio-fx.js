/* ============================================================
   BIG BROTHER V7.0 — AUDIO FX & HAPTICS (WEB AUDIO API)
   Synthesizes military-grade tactile clicks, radar pulses,
   and threat alerts without any external audio asset dependencies.
   ============================================================ */

class TacticalAudioEngine {
    constructor() {
        this.ctx = null;
        try {
            this.enabled = typeof localStorage !== 'undefined' && localStorage.getItem('bb_audio_enabled') === 'true';
        } catch (e) {
            this.enabled = false;
        }
    }

    _initContext() {
        if (!this.ctx && typeof window !== 'undefined') {
            const AudioContext = window.AudioContext || window.webkitAudioContext;
            if (AudioContext) {
                this.ctx = new AudioContext();
            }
        }
        if (this.ctx && this.ctx.state === 'suspended') {
            this.ctx.resume();
        }
    }

    toggle() {
        this.enabled = !this.enabled;
        try {
            if (typeof localStorage !== 'undefined') {
                localStorage.setItem('bb_audio_enabled', this.enabled);
            }
        } catch (e) {}
        if (this.enabled) {
            this._initContext();
            this.playClick(900, 0.04);
        }
        return this.enabled;
    }

    playClick(freq = 850, duration = 0.03) {
        if (!this.enabled) return;
        try {
            this._initContext();
            if (!this.ctx) return;
            const osc = this.ctx.createOscillator();
            const gain = this.ctx.createGain();

            osc.type = 'sine';
            osc.frequency.setValueAtTime(freq, this.ctx.currentTime);
            osc.frequency.exponentialRampToValueAtTime(freq * 0.5, this.ctx.currentTime + duration);

            gain.gain.setValueAtTime(0.04, this.ctx.currentTime);
            gain.gain.exponentialRampToValueAtTime(0.001, this.ctx.currentTime + duration);

            osc.connect(gain);
            gain.connect(this.ctx.destination);

            osc.start();
            osc.stop(this.ctx.currentTime + duration);
        } catch (e) {
            // AudioContext autoplay restrictions or disabled
        }
    }

    playModuleLaunch() {
        if (!this.enabled) return;
        try {
            this._initContext();
            if (!this.ctx) return;
            const osc = this.ctx.createOscillator();
            const gain = this.ctx.createGain();

            osc.type = 'triangle';
            osc.frequency.setValueAtTime(420, this.ctx.currentTime);
            osc.frequency.linearRampToValueAtTime(980, this.ctx.currentTime + 0.09);

            gain.gain.setValueAtTime(0.035, this.ctx.currentTime);
            gain.gain.linearRampToValueAtTime(0.001, this.ctx.currentTime + 0.1);

            osc.connect(gain);
            gain.connect(this.ctx.destination);

            osc.start();
            osc.stop(this.ctx.currentTime + 0.1);
        } catch (e) {}
    }

    playScanPulse() {
        if (!this.enabled) return;
        try {
            this._initContext();
            if (!this.ctx) return;
            const osc = this.ctx.createOscillator();
            const gain = this.ctx.createGain();

            osc.type = 'sine';
            osc.frequency.setValueAtTime(1200, this.ctx.currentTime);
            osc.frequency.exponentialRampToValueAtTime(300, this.ctx.currentTime + 0.18);

            gain.gain.setValueAtTime(0.05, this.ctx.currentTime);
            gain.gain.exponentialRampToValueAtTime(0.0005, this.ctx.currentTime + 0.18);

            osc.connect(gain);
            gain.connect(this.ctx.destination);

            osc.start();
            osc.stop(this.ctx.currentTime + 0.18);
        } catch (e) {}
    }

    playThreatAlert() {
        if (!this.enabled) return;
        try {
            this._initContext();
            if (!this.ctx) return;
            const now = this.ctx.currentTime;
            [
                { freq: 950, time: now },
                { freq: 1300, time: now + 0.08 }
            ].forEach(({ freq, time }) => {
                const osc = this.ctx.createOscillator();
                const gain = this.ctx.createGain();
                osc.type = 'sawtooth';
                osc.frequency.setValueAtTime(freq, time);

                gain.gain.setValueAtTime(0.04, time);
                gain.gain.exponentialRampToValueAtTime(0.001, time + 0.07);

                osc.connect(gain);
                gain.connect(this.ctx.destination);

                osc.start(time);
                osc.stop(time + 0.07);
            });
        } catch (e) {}
    }
}

window.tacticalAudio = new TacticalAudioEngine();
