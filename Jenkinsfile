pipeline {
    agent any

    environment {
        SONAR_PROJECT_KEY = 'tu-proyecto'
        DOCKER_IMAGE      = 'tu-app:latest'
        // Umbral: el pipeline falla si hay vulnerabilidades de esta severidad o mayor
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
                        publishHTML(target: [
                            reportName: 'Gitleaks Report',
                            reportDir: '.',
                            reportFiles: 'gitleaks-report.json'
                        ])
                        error('🚨 SECRETS DETECTADOS en el código. Pipeline detenido.')
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
                    semgrep --config=p/python \
                            --config=p/flask \
                            --config=p/owasp-top-ten \
                            . || true
                '''
                // Cuenta hallazgos críticos y falla si hay alguno
                script {
                    def report = readJSON file: 'semgrep-report.json'
                    def critical = report.results.findAll { it.extra.severity == 'ERROR' }
                    echo "Semgrep encontró ${critical.size()} hallazgos críticos"
                    if (critical.size() > 0) {
                        error("🚨 SAST: ${critical.size()} vulnerabilidades críticas encontradas.")
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
                withSonarQubeEnv('SonarQube') {
                    sh '''
                        sonar-scanner \
                          -Dsonar.projectKey=${SONAR_PROJECT_KEY} \
                          -Dsonar.sources=. \
                          -Dsonar.host.url=http://localhost:9000
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
                    waitForQualityGate abortPipeline: true
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
                        --exit-code 1 \
                        --severity ${TRIVY_SEVERITY} \
                        --format json \
                        --output trivy-report.json \
                        ${DOCKER_IMAGE} || true
                '''
                script {
                    def report = readJSON file: 'trivy-report.json'
                    def vulns = report.Results?.collectMany { it.Vulnerabilities ?: [] }
                                      .findAll { it.Severity in ['HIGH', 'CRITICAL'] }
                    echo "Trivy encontró ${vulns?.size() ?: 0} vulns HIGH/CRITICAL"
                    if (vulns && vulns.size() > 0) {
                        error("🚨 TRIVY: ${vulns.size()} vulnerabilidades HIGH/CRITICAL en la imagen.")
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
                echo '✅ App desplegada en http://localhost:5001 para DAST (semana 3)'
            }
        }
    }

    // ─────────────────────────────────────────
    // RESUMEN final del pipeline
    // ─────────────────────────────────────────
    post {
        success {
            echo '✅ Pipeline completo — NINGUNA vulnerabilidad crítica detectada.'
        }
        failure {
            echo '❌ Pipeline detenido — revisar reportes archivados.'
        }
        always {
            // Aquí en semana 3 vas a agregar OWASP ZAP
            echo 'Reportes disponibles en Artifacts de este build.'
        }
    }
}