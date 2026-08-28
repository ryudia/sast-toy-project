class Evaluator:
    def __init__(self, ground_truth: dict, detections: dict):
        """
        ground_truth: {file_path: bool (취약점 존재 여부)}
        detections: {file_path: bool (탐지 여부)}
        """
        self.ground_truth = ground_truth
        self.detections = detections

    def evaluate(self):
        tp = 0
        fp = 0
        fn = 0
        tn = 0

        for file_path, is_vulnerable in self.ground_truth.items():
            detected = self.detections.get(file_path, False)

            if is_vulnerable and detected:
                tp += 1
            elif not is_vulnerable and detected:
                fp += 1
            elif is_vulnerable and not detected:
                fn += 1
            elif not is_vulnerable and not detected:
                tn += 1

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0

        return {
            "TP": tp,
            "FP": fp,
            "FN": fn,
            "TN": tn,
            "Precision": precision,
            "Recall": recall
        }

    def print_results(self):
        res = self.evaluate()
        print("Evaluation Results")
        print("-" * 18)
        print(f"TP: {res['TP']}")
        print(f"FP: {res['FP']}")
        print(f"FN: {res['FN']}")
        print(f"TN: {res['TN']}")
        print()
        print(f"Precision: {res['Precision']:.4f}")
        print(f"Recall:    {res['Recall']:.4f}")