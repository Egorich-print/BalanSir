// Универсальный Jenkinsfile для репозиториев GitHub аккаунта Egorich-print.
//
// Принципы (по схеме CI/CD-инфраструктуры оператора):
//   * единая очередь Jenkins (numExecutors=1) — тяжёлые сборки не дублируются;
//   * дополнительно flock на общем lock-файле — та же блокировка, если ту же
//     машину используют другие раннеры;
//   * push в ветку -> проверки; Pull Request -> проверки; тег v* -> релиз;
//   * без входящих webhooks: GitHub опрашивается планировщиком
//     (PeriodicFolderTrigger в multibranch-проекте, интервал 5 мин),
//     публичного адреса у Jenkins нет;
//   * релиз публикуется только после успешных проверок.
//
// ГЛАВНОЕ ПРАВИЛО: Jenkins НЕ ДУБЛИРУЕТ логику проверок репозитория.
// Если в репозитории есть собственный гейт-скрипт (scripts/gate.sh,
// scripts/ci.sh, scripts/ci/check.sh) — вызывается он, потому что там
// зафиксированы настоящие гейты проекта. Только если гейт-скрипта нет,
// применяется базовый набор по типу проекта.
//
// Релиз по тегу публикуется ТОЛЬКО если в репозитории нет своего
// release-workflow (.github/workflows/release*.yml) — иначе GitHub Actions и
// Jenkins создали бы один и тот же релиз дважды.
//
// ВАЖНО про порядок шагов:
//   checkout scm идёт ПЕРЕД определением типа проекта и гейт-скрипта.
//   fileExists() до checkout смотрит в пустой workspace — тип всегда
//   определялся как "shell", а родной гейт-скрипт и GIT_URL не находились
//   никогда. Та же поправка нужна и для GIT_URL: переменные SCM
//   (GIT_URL, GIT_COMMIT) появляются только после checkout.
//
// ВАЖНО про shell:
//   Шаг `sh` в Jenkins выполняет скрипт через /bin/sh, а на Debian это dash.
//   Поэтому все встроенные скрипты POSIX-совместимы: никаких process
//   substitution (<(...)), [[ ]], массивов. Bash-ism в скрипте даёт
//   "Syntax error: redirection unexpected" и падает до выполнения.
//   Скрипты самого репозитория (scripts/gate.sh и т.п.) запускаются
//   напрямую и используют собственный shebang.
//
// Пути (LXC 120 на pve-xeon):
//   /var/lib/jenkins/workspace         -> sdb1, SSD P4-240 (240 МБ/с)
//   /var/lib/jenkins/workspace/.cargo-target -> тот же SSD, кэш cargo
//   /var/lib/jenkins/.cargo            -> CARGO_HOME (sdg1)
//   /srv/jenkins/tmp                   -> sdf1 (42 МБ/с) — временное
//   /srv/jenkins/archive               -> sdc1 (78 МБ/с) — артефакты
//
// Блокировка: flock /var/lib/jenkins/ci/build.lock (путь внутри контейнера).

pipeline {
    agent any

    options {
        timestamps()
        timeout(time: 120, unit: 'MINUTES')
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '30', artifactNumToKeepStr: '10'))
        skipDefaultCheckout(true)
    }

    environment {
        LOCK_FILE          = '/var/lib/jenkins/ci/build.lock'
        CARGO_HOME         = '/var/lib/jenkins/.cargo'
        RUSTUP_HOME        = '/var/lib/jenkins/.rustup'
        CARGO_TARGET_DIR   = '/var/lib/jenkins/workspace/.cargo-target'
        RUST_BACKTRACE     = '1'
        RUST_BACKTRACE_FULL = '1'
        // rustup подхватывает версию из rust-toolchain.toml репозитория
        // (1.99.0 / 1.98.0 / stable — все три установлены в контейнере).
        PATH               = '/var/lib/jenkins/.cargo/bin:/opt/node24/bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin'
    }

    stages {

        stage('Подготовка') {
            steps {
                // Сначала код репозитория — только потом можно определить
                // тип проекта, найти гейт-скрипт и взять GIT_URL.
                checkout scm
                script {
                    if (fileExists('Cargo.toml')) {
                        env.PROJECT_TYPE = 'rust'
                    } else if (fileExists('package.json')) {
                        env.PROJECT_TYPE = 'node'
                    } else if (fileExists('Makefile') || fileExists('Justfile')) {
                        env.PROJECT_TYPE = 'make'
                    } else {
                        env.PROJECT_TYPE = 'shell'
                    }

                    // Репозиторий для gh release: из GIT_URL (https://github.com/<owner>/<repo>.git).
                    def m = (env.GIT_URL ?: '').replaceAll('\\.git$', '').split('/')
                    env.GH_REPO = m.size() >= 2 ? "${m[-2]}/${m[-1]}" : ''

                    // Свой гейт-скрипт репозитория — приоритет над базовым набором.
                    def gates = [
                        'scripts/gate.sh',
                        'scripts/ci.sh',
                        'scripts/ci/check.sh',
                        'tools/gate.sh',
                    ]
                    env.REPO_GATE = gates.find { fileExists(it) } ?: ''

                    // Свой release-workflow — тогда релиз создаёт он, а не Jenkins.
                    env.REPO_HAS_RELEASE = fileExists('.github/workflows/release.yml') ||
                                          fileExists('.github/workflows/release.yaml') ||
                                          fileExists('.github/workflows/ide-release.yml')

                    def ref = env.TAG_NAME ?: env.BRANCH_NAME ?: '-'
                    currentBuild.displayName = "#${env.BUILD_NUMBER} ${env.PROJECT_TYPE} ${ref}"
                    currentBuild.description = "repo=${env.GH_REPO} ref=${ref} commit=${env.GIT_COMMIT?.take(8)}"
                    echo "Тип проекта: ${env.PROJECT_TYPE}"
                    echo "Репозиторий: ${env.GH_REPO ?: 'не определён'}"
                    echo "Гейт-скрипт репозитория: ${env.REPO_GATE ?: 'нет — базовый набор'}"
                    echo "Свой release-workflow: ${env.REPO_HAS_RELEASE ? 'есть — релиз создаёт он' : 'нет'}"
                }
                sh '''
                    set -e
                    mkdir -p /var/lib/jenkins/ci "$(dirname "${CARGO_TARGET_DIR}")"
                    touch "${LOCK_FILE}"
                    df -h "$(dirname "${CARGO_TARGET_DIR}")" | tail -1
                '''
            }
        }

        stage('Проверки и тесты') {
            steps {
                script {
                    if (env.REPO_GATE) {
                        // Родной гейт репозитория: не дублируем его логику.
                        // Запускаем напрямую — шебанг скрипта репозитория
                        // сам выбирает интерпретатор (bash/posix).
                        sh """
                            set -e
                            chmod +x '${env.REPO_GATE}' 2>/dev/null || true
                            flock "${LOCK_FILE}" './${env.REPO_GATE}'
                        """
                    } else {
                        switch (env.PROJECT_TYPE) {
                            case 'rust':
                                sh '''
                                    set -e
                                    rustc --version
                                    cargo --version
                                    rustup show active-toolchain || true
                                    # fmt — предупреждение: в части репозиториев
                                    # (Antigravity) дерево намеренно не отформатировано,
                                    # и строгий гейт остаётся в CI самого репозитория.
                                    flock "${LOCK_FILE}" cargo fmt --all -- --check || echo "WARN: cargo fmt --check не пройден (строгий гейт — в CI репозитория)"
                                    # clippy без -D warnings: реальные ошибки компиляции
                                    # валят сборку, а предупреждения — зона CI репозитория.
                                    flock "${LOCK_FILE}" cargo clippy --all-targets --all-features
                                    flock "${LOCK_FILE}" cargo test --all-targets
                                '''
                                break
                            case 'node':
                                sh '''
                                    set -e
                                    node --version
                                    npm --version
                                    npm ci
                                    flock "${LOCK_FILE}" npm run lint
                                    flock "${LOCK_FILE}" npm test
                                '''
                                break
                            case 'make':
                                sh '''
                                    set -e
                                    if command -v just >/dev/null 2>&1 && [ -f Justfile ]; then
                                      flock "${LOCK_FILE}" just --list >/dev/null
                                    else
                                      make -n >/dev/null
                                    fi
                                '''
                                break
                            default:
                                // shell-проекты: синтаксис всех tracked *.sh и *.py.
                                // Списки — во временные файлы: перенаправление
                                // "done < file" работает в dash, process
                                // substitution "<(...)" — нет.
                                sh '''
                                    set -e
                                    fail=0
                                    git ls-files '*.sh' > /tmp/jenkins_gate_sh.txt || true
                                    while IFS= read -r f; do
                                      [ -n "$f" ] || continue
                                      bash -n "$f" || { echo "syntax error: $f"; fail=1; }
                                    done < /tmp/jenkins_gate_sh.txt
                                    git ls-files '*.py' > /tmp/jenkins_gate_py.txt || true
                                    if command -v python3 >/dev/null 2>&1; then
                                      while IFS= read -r f; do
                                        [ -n "$f" ] || continue
                                        python3 -m py_compile "$f" || { echo "python error: $f"; fail=1; }
                                      done < /tmp/jenkins_gate_py.txt
                                    fi
                                    [ "$fail" = 0 ] || exit 1
                                    echo "все tracked shell/python скрипты разбираются"
                                '''
                        }
                    }
                }
            }
        }

        stage('Сборка') {
            steps {
                script {
                    switch (env.PROJECT_TYPE) {
                        case 'rust':
                            sh '''
                                set -e
                                flock "${LOCK_FILE}" cargo build --release
                                mkdir -p /srv/jenkins/archive/"${JOB_NAME}"
                                # Копируем бинарники в архив через xargs -0 + cp -t.
                                #
                                # НЕЛЬЗЯ писать find ... -exec cp -p {} DEST + :
                                # в форме "+" GNU find требует, чтобы "{}" был
                                # ПОСЛЕДНИМ аргументом команды (man find:
                                # "it must appear at the end, immediately before
                                # the +"). Иначе find не находит терминатор и
                                # падает с "missing argument to `-exec'".
                                # xargs -0 (безопасные пробелы) + cp -t (каталог
                                # назначения) дают правильный порядок аргументов.
                                find "${CARGO_TARGET_DIR}/release" -maxdepth 1 -type f -perm -u+x -print0 \
                                    | xargs -0 -r cp -p -t /srv/jenkins/archive/"${JOB_NAME}"/
                                ls -la /srv/jenkins/archive/"${JOB_NAME}" || true
                            '''
                            break
                        case 'node':
                            sh '''
                                set -e
                                flock "${LOCK_FILE}" npm run build --if-present
                            '''
                            break
                        default:
                            echo "сборка для типа ${env.PROJECT_TYPE} не определена"
                    }
                }
            }
        }

        stage('Релиз') {
            when {
                buildingTag()
                allOf {
                    // В декларативном DSL условие "not" требует блок:
                    // "not changeRequest()" — синтаксическая ошибка компиляции
                    // ("No additional arguments are allowed for children").
                    not { changeRequest() }
                    expression { env.TAG_NAME != null }
                }
            }
            steps {
                script {
                    if (env.REPO_HAS_RELEASE) {
                        echo 'В репозитории есть свой release-workflow — релиз создаёт он, Jenkins не дублирует.'
                        return
                    }
                    if (!env.GH_REPO) {
                        error 'не удалось определить репозиторий из GIT_URL — релиз не публикуем'
                    }
                    def tag = env.TAG_NAME ?: env.GIT_TAG
                    echo "Публикация релиза ${tag} для ${env.GH_REPO}"
                }
                sh '''
                    set -e
                    mkdir -p dist
                    if [ -d /srv/jenkins/archive/"${JOB_NAME}" ]; then
                      cp -a /srv/jenkins/archive/"${JOB_NAME}"/. dist/ 2>/dev/null || true
                    fi
                    ( cd dist && sha256sum * > SHA256SUMS ) 2>/dev/null || true
                    ls -la dist
                '''
                script {
                    def token = withCredentials([string(credentialsId: 'github-token', variable: 'GH_TOKEN')]) {
                        return sh(script: 'echo "$GH_TOKEN"', returnStdout: true).trim()
                    }
                    def hasAssets = sh(script: 'ls dist 2>/dev/null | wc -l', returnStdout: true).trim().toInteger() > 0
                    if (!hasAssets) {
                        echo 'Артефактов нет — релиз без вложений создавать не буду'
                        return
                    }
                    sh """
                        set -e
                        export GH_TOKEN='${token}'
                        gh release create '${env.TAG_NAME}' dist/* --verify-tag --generate-notes --repo '${env.GH_REPO}'
                    """
                }
            }
        }
    }

    post {
        always {
            // Рабочий каталог чистим, кэш cargo НЕ чистим — он и есть смысл
            // переноса на SSD (240 МБ/с против 42 МБ/с на sdf1).
            deleteDir()
        }
        failure {
            echo "Сборка ${env.JOB_NAME} #${env.BUILD_NUMBER} упала. Логи: ${env.BUILD_URL}"
        }
    }
}
