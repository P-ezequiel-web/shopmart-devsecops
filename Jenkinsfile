pipeline {
    agent any

    environment {
        SONAR_PROJECT_KEY = 'tu-proyecto'
        DOCKER_IMAGE      = 'tu-app:latest'
        // Umbral de severidad para reportar
        TRIVY_SEVERITY    = 'HIGH,CRITICAL'
    }

    stages {

        // ─────────────────────────────────────────
        // STAGE 1: Detección de secretos en el código
        // ─────────────────────────────────────────
        stage('Secrets Scan (Gitleaks)') {
            steps {
                script {
                    def result = sh(
                        script: 'gitleaks detect --source . --report-format json --report-path gitleaks-report.json --exit-code 1',
                        returnStatus: true
                    )
                    if (result != 0) {
                        echo "⚠️ ALERTA: Gitleaks detectó secretos en el código. Continuando con el pipeline..."
                        currentBuild.result = 'UNSTABLE'
                    } else {
                        echo "✅ Gitleaks: No se detectaron secretos."
                    }
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'gitleaks-report.json', allowEmptyArchive: true
                }
            }
        }

        // ─────────────────────────────────────────
        // STAGE 2: SAST con Semgrep
        // ─────────────────────────────────────────
        stage('SAST (Semgrep)') {
            steps {
                sh '''
                    semgrep --config=auto \
                            --json \
                            --output=semgrep-report.json \
                            --severity=ERROR \
                            . || true
                '''
                script {
                    def report = readJSON file: 'semgrep-report.json'
                    def critical = report.results.findAll { it.extra.severity == 'ERROR' }
                    echo "Semgrep encontró ${critical.size()} hallazgos críticos"
                    if (critical.size() > 0) {
                        echo "⚠️ ALERTA: Semgrep encontró ${critical.size()} vulnerabilidades críticas. Continuando con el pipeline..."
                        currentBuild.result = 'UNSTABLE'
                    } else {
                        echo "✅ Semgrep: Sin hallazgos críticos."
                    }
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'semgrep-report.json', allowEmptyArchive: true
                }
            }
        }

        // ─────────────────────────────────────────
        // STAGE 3: SAST con SonarQube
        // ─────────────────────────────────────────
        stage('SAST (SonarQube)') {
            steps {
                withSonarQubeEnv('sonar-ci') {
                    sh '''
                        sonar-scanner \
                          -Dsonar.projectKey=${SONAR_PROJECT_KEY} \
                          -Dsonar.sources=. \
                          -Dsonar.host.url=http://192.168.100.61:9000
                    '''
                }
            }
        }

        // ─────────────────────────────────────────
        // STAGE 4: Quality Gate de SonarQube
        // ─────────────────────────────────────────
        stage('Quality Gate') {
            steps {
                timeout(time: 5, unit: 'MINUTES') {
                    script {
                        def qg = waitForQualityGate(abortPipeline: false)
                        if (qg.status != 'OK') {
                            echo "⚠️ ALERTA: El Quality Gate de SonarQube no fue superado (Estado: ${qg.status}). Continuando con el pipeline..."
                            currentBuild.result = 'UNSTABLE'
                        } else {
                            echo "✅ SonarQube Quality Gate superado exitosamente."
                        }
                    }
                }
            }
        }

        // ─────────────────────────────────────────
        // STAGE 5: Build Docker image
        // ─────────────────────────────────────────
        stage('Build Docker Image') {
            steps {
                sh 'docker build -t ${DOCKER_IMAGE} .'
            }
        }

        // ─────────────────────────────────────────
        // STAGE 6: SCA + Container scan (Trivy)
        // ─────────────────────────────────────────
        stage('Container & Dependency Scan (Trivy)') {
            steps {
                sh '''
                    trivy image \
                        --exit-code 0 \
                        --severity ${TRIVY_SEVERITY} \
                        --format json \
                        --output trivy-report.json \
                        ${DOCKER_IMAGE} || true
                '''
                script {
                    def report = readJSON file: 'trivy-report.json'
                    def vulns = report.Results?.collectMany { it.Vulnerabilities ?: [] }
                                            ?.findAll { it.Severity in ['HIGH', 'CRITICAL'] }
                    echo "Trivy encontró ${vulns?.size() ?: 0} vulns HIGH/CRITICAL"
                    if (vulns && vulns.size() > 0) {
                        echo "⚠️ ALERTA: Trivy encontró ${vulns.size()} vulnerabilidades HIGH/CRITICAL en la imagen. Continuando con el pipeline..."
                        currentBuild.result = 'UNSTABLE'
                    } else {
                        echo "✅ Trivy: No se encontraron vulnerabilidades HIGH/CRITICAL."
                    }
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'trivy-report.json', allowEmptyArchive: true
                }
            }
        }

        // ─────────────────────────────────────────
        // STAGE 7: Deploy a staging (Docker local)
        // ─────────────────────────────────────────
        stage('Deploy Staging') {
            steps {
                sh '''
                    docker stop staging-app || true
                    docker rm   staging-app || true
                    docker run -d \
                        --name staging-app \
                        -p 5001:5000 \
                        ${DOCKER_IMAGE}
                '''
                echo '✅ App desplegada en http://localhost:5001 para DAST'
            }
        }
    }

    // ─────────────────────────────────────────
    // RESUMEN final del pipeline
    // ─────────────────────────────────────────
    post {
        success {
            echo '✅ Pipeline completado con éxito — NINGUNA vulnerabilidad detectada.'
        }
        unstable {
            echo '⚠️ Pipeline completado con advertencias — Se detectaron vulnerabilidades, pero se entregó el reporte completo y la aplicación fue desplegada (Build marcado como UNSTABLE).'
        }
        failure {
            echo '❌ Pipeline falló por un error crítico de ejecución (no relacionado con hallazgos de seguridad).'
        }
        always {
            echo '📁 Todos los reportes de seguridad están disponibles en la sección Artifacts de este build.'
        }
    }
}
